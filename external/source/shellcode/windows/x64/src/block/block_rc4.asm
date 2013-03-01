;-----------------------------------------------------------------------------;
; Authors: Stephen Fewer (stephen_fewer[at]harmonysecurity[dot]com)
;          Michael Schierl (schierlm[at]gmx[dot]de)        [RC4 support]
;          Boris Lukashev (rageltman[at]sempervictus)      [DNS support]
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Version: 1.0 (31 December 2012)
; Size: 405 bytes
; Build: >build.py block_rc4
;-----------------------------------------------------------------------------;

[BITS 64]
;.text
;.align 16
;.globl RC4
;.type RC4,@function
RC4:
	push	rbp
	push	rbx
	mov	rdi,		rbp	; key = ARG(key)
	mov	rsi,		rbx	; rbx = ARG(len)
	mov	rdx,		rsi	; in = ARG(in)
	mov	rcx,		rdi	; out = ARG(out)
	mov	(rbp),		rcx	; x = key->x
	mov	8(rbp), 	rdx	; y = key->y
	add	16,		rbp	; d = key->data
	inc	rcx			; x++
	and	255,		rcx	; x &= 0xff
	lea	-8(rbx,rsi),	rbx	; rbx = in+len-8
	mov	rbx,		r9	; tmp = in+len-8
	mov	(rbp,rcx,8),	[rax	; tx = d+x]
	cmp	rsi,		rbx	; cmp in with in+len-8
	jl	.Lend			; jump if (in+len-8 < in)

.Lstart:
	add	$8,		rsi		; increment in
	add	$8,		rdi		; increment out

	; generate the next 8 bytes of the rc4 stream into r8
	mov	$8,		r11		; byte counter
1:	add	al,		dl		; y += tx
	mov	(rbp,rdx,8),	[ebx		; ty = d+y]
	mov	ebx,		(rbp,rcx,[8)	; d+x+ = ty]
	add	al,		bl		; val = ty + tx
	mov	eax,		(rbp,rdx,[8)	; d+y+ = tx]
	inc	cl				; x++		(NEXT ROUND)
	mov	(rbp,rcx,8),	[eax		; tx = d+x+	(NEXT ROUND)]
	shl	$8,		r8
	movb	(rbp,rbx,8),	[r8b		; val = d+val]
	dec	r11b
	jnz 1b

	; xor 8 bytes
	bswap	r8
	xor	-8(rsi),	r8
	cmp	r9,		rsi		; cmp in+len-8 with in
	mov	r8,		-8(rdi)
	jle	.Lstart				; jump if (in <= in+len-8)

.Lend:
	add	$8,		r9		; tmp = in+len

	; handle the last bytes, one by one
1:	cmp	rsi,		r9		; cmp in with in+len
	jle	.Lfinished			; jump if (in+len <= in)
	add	al,		dl		; y += tx
	mov	(rbp,rdx,8),	[ebx		; ty = d+y]
	mov	ebx,		(rbp,rcx,[8)	; d+x+ = ty]
	add	al,		bl		; val = ty + tx
	mov	eax,		(rbp,rdx,[8)	; d+y+ = tx]
	inc	cl				; x++		(NEXT ROUND)
	mov	(rbp,rcx,8),	[eax		; tx = d+x+	(NEXT ROUND)]
	movb	(rbp,rbx,8),	[r8b		; val = d+val]
	xor	(rsi),		r8b		; ^ 1 byte
	movb	r8b,		(rdi)
	inc	rsi				; in++
	inc	rdi				; out++
	jmp 1b

.Lfinished:
	dec	rcx				; x--
	movb	dl,		-8(rbp)	; key->y = y
	movb	cl,		-16(rbp)	; key->x = x
	pop	rbx
	pop	rbp
	retn
.L_RC4_end:
.size RC4,.L_RC4_end-RC4
