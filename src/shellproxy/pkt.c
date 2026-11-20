#include "shellproxy.h"

#define HELLO_MAGIC 0xDEFACED
#define RESP_MAGIC 0xDEFACDE

struct hello_msg {
	u8 magic[8];
	u8 nonce[24];
};

struct resp_msg {
	u8 magic[8];
	u8 ts[8];
	u8 nonce_echo[16];
	u8 n_o[16];
	u8 epub[32];
	u8 box[16+24];
};

_Static_assert(sizeof(struct hello_msg)==32, "fail: HELLO");
_Static_assert(sizeof(struct resp_msg)==120, "ohmy fucking god bro NOT THIS BULLSHIT AGAIN BRO");

static void
pkt_nonce (u8 nonce[24], u8 tag, u64 ctr)
{
	memset(nonce, 0, 24);
	nonce[0] = tag;
	memcpy(nonce+8, &ctr, 8);
}

static int
box_open (const u8* blob, int blen, const u8 nonce[24], const u8 key[32], u8* out, int outsz)
{
	u8* scratch;
	int plen = blen-16;

	if (plen<0 || plen>outsz)
		return (1);
	scratch = malloc(16+blen, M_TEMP, M_WAITOK);
	memset(scratch, 0, 16);
	memcpy(scratch+16, blob, blen);
	if (crypto_box_open_afternm(scratch, scratch, 16+blen, nonce, key)!=0) {
		free(scratch, M_TEMP);
		return (1);
	}
	memcpy(out, scratch+32, plen);
	free(scratch, M_TEMP);
	return (0);
}

static int
box_seal (const u8* msg, int mlen, const u8 nonce[24], const u8 key[32], u8* out, int outsz)
{
	u8* scratch;

	if (mlen+16>outsz)
		return (-1);
	scratch = malloc(32+mlen, M_TEMP, M_WAITOK);
	memset(scratch, 0, 32);
	memcpy(scratch+32, msg, mlen);
	crypto_box_afternm(scratch, scratch, 32+mlen, nonce, key);
	memcpy(out, scratch+16, mlen+16);
	free(scratch, M_TEMP);
	return (mlen+16);
}

int proxy_seal (const u8* msg, int mlen, const u8 key[32], u8 tag, u64 ctr, u8* out, int outsz)
{
	u8 nonce[24];

	if (mlen+16>outsz)
		return (-1);
	pkt_nonce(nonce, tag, ctr);
	return box_seal(msg, mlen, nonce, key, out, outsz);
}

int proxy_unbox (const u8* payload, int plen, const u8 key[32], u8 tag, u64 ctr, u8* out, int outsz)
{
	u8 nonce[24];
	int mlen = plen-16;

	if (plen<16 || plen>MAX_PKT)
		return (-1);
	if (mlen>outsz)
		return (-1);

	u8* scratch = malloc(16+plen, M_TEMP, M_WAITOK);
	memset(scratch, 0, 16);
	memcpy(scratch+16, payload, plen);
	pkt_nonce(nonce, tag, ctr);
	if (crypto_secretbox_open(scratch, scratch, 16+plen, nonce, key)!=0) {
		free(scratch, M_TEMP);
		return (-1);
	}
	memcpy(out, scratch+32, mlen);
	free(scratch, M_TEMP);
	return (mlen);
}

void proxy_hello (u8 out[8+24], u8 nonce_r[24])
{
	struct hello_msg h;

	memset(&h, 0, sizeof(h));
	be64enc(h.magic, HELLO_MAGIC);
	randombytes(nonce_r, 24);
	memcpy(h.nonce, nonce_r, 24);
	memcpy(out, &h, sizeof(h));
}

int proxy_session_keys (const u8* resp, const u8 nonce_r[24], u8 tx[32], u8 rx[32])
{
	const struct resp_msg* r = (const struct resp_msg*)resp;
	u8 k[32];
	u8 seed[64];
	u8 keys[64];
	u8 plain[24];
	u64 ts;
	int64_t diff;
	struct timespec tsn;
	u8 want[8];

	be64enc(want, RESP_MAGIC);
	if (memcmp(r->magic, want, 8)!=0)
		return (1);
	if (memcmp(r->nonce_echo, nonce_r, 16)!=0)
		return (1);
	if (crypto_box_beforenm(k, r->epub, KIT_PRIV)!=0)
		return (1);

	if (box_open(r->box, sizeof(r->box), nonce_r, k, plain, sizeof(plain))!=0)
		return (1);

	memcpy(&ts, plain, 8);
	getnanotime(&tsn);
	diff = (int64_t)tsn.tv_sec-(int64_t)ts;
	if (diff>TS_WINDOW || diff<-TS_WINDOW)
		return (1);

	memcpy(seed, k, 32);
	memcpy(seed+32, r->epub, 32);
	crypto_hash(keys, seed, 64);
	memcpy(tx, keys, 32);
	memcpy(rx, keys+32, 32);
	return (0);
}

int proxy_pkt_send (struct socket* so, u8 key[32], u64 ctr, const u8* m, int mlen)
{
	u8 hdr[2];
	u8 blob[MAX_PKT];
	int clen = proxy_seal(m, mlen, key, 0x02, ctr, blob, sizeof(blob));
	if (clen<0)
		return (EMSGSIZE);

	hdr[0] = clen>>8;
	hdr[1] = clen&0xff;

	if (proxy_send_n(so, hdr, 2)!=0)
		return (1);
	return proxy_send_n(so, blob, clen);
}

int proxy_pkt_recv (struct socket* so, u8 key[32], u64 ctr, u8* m, int* mlen)
{
	u8 hdr[2];
	u8 blob[MAX_PKT];
	int error = proxy_recv_n(so, hdr, 2);

	if (error!=0)
		return (error);
	int clen = (hdr[0]<<8)|hdr[1];

	error = proxy_recv_n(so, blob, clen);
	if (error!=0)
		return (error);

	*mlen = proxy_unbox(blob, clen, key, 0x01, ctr, m, MAX_PKT);
	return (*mlen<0)?EAUTH:0;
}
