#include <sys/libkern.h>
#include "subnet.h"

int subnet_hex_decode (const char* text, unsigned char* out, int outsz)
{
	int len = 0;

	// maybe a memory ocrruption bug here someone please check
	while (*text && len<outsz) {
		// if whitespace, keep going
		while (*text==' ' || *text=='\t')
			text++;
		// if nullbyte, we're done
		if (text[0]=='\0' || text[1]=='\0') return (-1);

		char pair[3] = { text[0], text[1], '\0' };
		char* end = NULL;
		// decode it
		unsigned long value = strtoul(pair, &end, 16);
		if (end!= pair+2 || value>0xff) return (-1);

		out[len++] = (unsigned char)value;
		text += 2;
	}
	return (len);
}
