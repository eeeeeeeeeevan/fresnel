# output .bin files get embedded into the injector by build.c.
# compiles our fileless magic code to shellcode (mainly shutdown handler)
# pe.S is for privesc. more will be explained in readme.

CFLAGS = -Os -ffreestanding -nostdlib -fno-stack-protector \
         -fomit-frame-pointer -mno-red-zone -mno-mmx -mno-sse -fno-pic

BINS = shutdown.bin

all: $(BINS)

shutdown.bin: shutdown_handler.c
	cc $(CFLAGS) -c $< -o shutdown_handler.o
	objcopy -O binary -j .text shutdown_handler.o $@
	@echo "+ $(notdir $@) $(shell wc -c < $@) bytes"

clean:
	rm -f *.o *.bin
