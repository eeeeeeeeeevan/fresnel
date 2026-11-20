KMOD=	shellproxy
SRCS=	shellproxy.c pktfmt.c pkt.c execute.c hide.c attr.c subnet.c discover.c dd.c mqtt.c keylog.c ../lib/ttylog.c ../lib/subnet_tcp.c ../lib/subnet_hex.c \
	../lib/tweetnacl/tweetnacl.c ../lib/mqttc/mqtt.c ../lib/mqttc/mqtt_pal.c \
	../lib/remsocket.c ../lib/remmqtt.c ../lib/remws.c ../lib/bq_websocket/bq_websocket_kernel.c
CFLAGS+=	-std=gnu11 -Wno-error=implicit-function-declaration -Wno-error=cast-qual -Wno-error=strict-prototypes -Wno-error=unused-variable -I.. -I../include -I/usr/src/sys/amd64/include -I/usr/src/sys/x86/include -I/usr/src/sys/i386/include -I../lib/tweetnacl -I../lib/mqttc -I../lib/bq_websocket -I../lib/bq_websocket/compat

.include <bsd.kmod.mk>
