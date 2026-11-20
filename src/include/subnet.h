#ifndef SUBNET_H
#define SUBNET_H

struct socket;

#define SUBNET_MAX_PAYLOAD 2048

int subnet_handle (const char* cmd, char* resp, int rsz);
int subnet_discover (char* resp, int rsz);
int subnet_tcp_connect (const char* ip, int port, struct socket** so);
int subnet_tcp_read (struct socket* so, unsigned char* buf, int len);
int subnet_tcp_write (struct socket* so, const unsigned char* buf, int len);
int subnet_hex_decode (const char* text, unsigned char* out, int outsz);

#endif
