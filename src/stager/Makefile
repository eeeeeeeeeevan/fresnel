MK_SSP= no
KMOD= stager
SRCS= stager.c persist.c vnode_if.h
CFLAGS+= -fno-stack-protector -fno-pic -mno-red-zone -I.. -I../include
.include <bsd.kmod.mk>
