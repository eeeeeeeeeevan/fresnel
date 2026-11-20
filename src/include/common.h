#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>

#include <vm/vm.h>
#include <vm/vm_page.h>

typedef vm_offset_t vmoffset;
typedef vm_page_t vmpg;
typedef vm_object_t vmobject;
typedef size_t size;

#define vmpgvalid vm_page_valid

#ifndef U8_TYPEDEF
#define U8_TYPEDEF
typedef unsigned char u8;
#endif
typedef uint16_t u16;
typedef uint32_t u32;
#ifndef U64_TYPEDEF
#define U64_TYPEDEF
typedef unsigned long long u64;
#endif
typedef register_t reg;
typedef uintptr_t uintptr;
typedef intptr_t intptr;
// sick of typing this shit over and over
#define volasm(...) __asm __volatile(__VA_ARGS__)

#endif
