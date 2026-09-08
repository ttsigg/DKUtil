/* Hand-written x86-64 test targets for the DKUtil Linux hook-mechanism
 * harness. See ../src/targets.h for what each symbol proves.
 *
 * Deliberately raw assembly, not compiler output: every hook test below
 * needs to know *exactly* what bytes sit at the hook address (a real call
 * rel32 for RelHook, a known-length NOP run for the ASM patch / cave, an
 * instruction whose encoding is RIP-relative for the stolen-bytes test).
 * Compiler-generated code can't promise any of that across a toolchain
 * bump; hand assembly can.
 */
	.intel_syntax noprefix
	.text

/* ---- RelHook target ----------------------------------------------- */

	.global original_callee
	.type original_callee, @function
original_callee:
	lea eax, [rdi + 1000]
	ret
	.size original_callee, . - original_callee

	.global relhook_target
	.type relhook_target, @function
relhook_target:
	push rbx
	mov ebx, edi
	.global relhook_callsite
relhook_callsite:
	call original_callee
	add eax, ebx
	pop rbx
	ret
	.size relhook_target, . - relhook_target

/* ---- AddASMPatch target --------------------------------------------- */

	.global asmpatch_target
	.type asmpatch_target, @function
asmpatch_target:
	mov eax, 7
	.global asmpatch_site
asmpatch_site:
	.rept 16
	nop
	.endr
	.global asmpatch_site_end
asmpatch_site_end:
	add eax, 1
	ret
	.size asmpatch_target, . - asmpatch_target

/* ---- AddCaveHook target: SysV register / SSE preservation ----------- */

	.global cavehook_target
	.type cavehook_target, @function
cavehook_target:
	/* cavehook_target is itself an ordinary SysV callee (main() calls it
	 * directly, compiler-generated on the caller side) — it must save its
	 * OWN caller's rbx/rbp/r12-r15 before clobbering them with sentinels
	 * below, and restore them before its own `ret`. This is unrelated to
	 * anything the cave hook does; it's this test target obeying the ABI
	 * contract it makes with main(). */
	push rbx
	push rbp
	push r12
	push r13
	push r14
	push r15

	movabs rbx, 0x1111111111111111
	movabs rbp, 0x2222222222222222
	movabs r12, 0x3333333333333333
	movabs r13, 0x4444444444444444
	movabs r14, 0x5555555555555555
	movabs r15, 0x6666666666666666
	movabs rax, 0x77777777AAAAAAAA
	movq xmm6, rax
	.global cavehook_site
cavehook_site:
	.rept 16
	nop
	.endr
	.global cavehook_site_end
cavehook_site_end:
	/* stash whatever the registers hold AFTER the cave into g_post[] */
	lea rax, [rip + g_post]
	mov [rax + 0],  rbx
	mov [rax + 8],  rbp
	mov [rax + 16], r12
	mov [rax + 24], r13
	mov [rax + 32], r14
	mov [rax + 40], r15
	movq [rax + 48], xmm6

	pop r15
	pop r14
	pop r13
	pop r12
	pop rbp
	pop rbx
	ret
	.size cavehook_target, . - cavehook_target

/* The hook callback the cave `call [rip]`s into. Hand-written on purpose:
 * a normal compiled C++ function would have its OWN prologue/epilogue
 * quietly restore rbx/rbp/r12-r15 before returning (they're SysV
 * callee-saved), which would make this test pass even if the fork's own
 * generated prolog/epilog around the call did nothing at all. Writing this
 * by hand means nothing but the fork's own trampoline code stands between
 * "clobbered here" and "restored to the host". */
	.global cavehook_callback
	.type cavehook_callback, @function
cavehook_callback:
	/* copy the prolog's g_pre[] snapshot into g_observed[], proving the
	 * callback can read a register snapshot the prolog built */
	lea rax, [rip + g_pre]
	lea rcx, [rip + g_observed]
	mov r8, [rax + 0]
	mov [rcx + 0], r8
	mov r8, [rax + 8]
	mov [rcx + 8], r8
	mov r8, [rax + 16]
	mov [rcx + 16], r8
	mov r8, [rax + 24]
	mov [rcx + 24], r8
	mov r8, [rax + 32]
	mov [rcx + 32], r8
	mov r8, [rax + 40]
	mov [rcx + 40], r8
	mov r8, [rax + 48]
	mov [rcx + 48], r8

	/* deliberately destroy the "preserved" registers */
	movabs rbx, 0xDEADDEADDEADDEAD
	movabs rbp, 0xDEADDEADDEADDEAD
	movabs r12, 0xDEADDEADDEADDEAD
	movabs r13, 0xDEADDEADDEADDEAD
	movabs r14, 0xDEADDEADDEADDEAD
	movabs r15, 0xDEADDEADDEADDEAD
	pxor xmm6, xmm6

	/* record rsp alignment at the point of this call (SysV requires 16B
	 * alignment immediately before a `call`) */
	mov rax, rsp
	and rax, 15
	lea rcx, [rip + g_callback_rsp_align]
	mov [rcx], rax
	ret
	.size cavehook_callback, . - cavehook_callback

/* ---- AddCaveHook target: stolen RIP-relative instruction ------------ */

	.global ripcave_target
	.type ripcave_target, @function
ripcave_target:
	.global ripcave_site
ripcave_site:
	lea rax, [rip + g_rip_target_value]  /* 48 8D 05 <disp32> -- 7 bytes */
	.global ripcave_site_end
ripcave_site_end:
	ret
	.size ripcave_target, . - ripcave_target

	.global ripcave_noop_callback
	.type ripcave_noop_callback, @function
ripcave_noop_callback:
	ret
	.size ripcave_noop_callback, . - ripcave_noop_callback

/* ---- AddCaveHook target: stolen movsxd (opcode 0x63) RIP-relative --- */
/* `movsxd rax, dword ptr [rip + g_movsxd_source]` (48 63 05 <disp32>, 7
 * bytes) -- the same ModRM/disp32 shape as ripcave_site's `lea`, but
 * exercises opcode 0x63 specifically (WASD's InsideUpdateInteractMove cave
 * steals a `movsxd rcx,[rdi+0x130]`, a non-RIP-relative use of the same
 * opcode; this target proves the RIP-relative relocation path for it). */

	.global movsxdcave_target
	.type movsxdcave_target, @function
movsxdcave_target:
	.global movsxdcave_site
movsxdcave_site:
	movsxd rax, dword ptr [rip + g_movsxd_source]  /* 48 63 05 <disp32> -- 7 bytes */
	.global movsxdcave_site_end
movsxdcave_site_end:
	ret
	.size movsxdcave_target, . - movsxdcave_target

	.global movsxdcave_noop_callback
	.type movsxdcave_noop_callback, @function
movsxdcave_noop_callback:
	ret
	.size movsxdcave_noop_callback, . - movsxdcave_noop_callback

/* ---- AddCaveHook target: undecodable stolen instruction (negative) -- */
/* A single `call qword ptr [rip+g_call_target_ptr]` (FF 15 <disp32>, 6
 * bytes) -- opcode 0xFF is outside Internal/CaveHook.hpp's minimal decoder
 * set. AddCaveHook must refuse to install this hook rather than replay or
 * guess-relocate it. Never actually invoked (the whole point is that the
 * hook install fails before Enable() ever patches the site), so the
 * pointer it reads never has to resolve to anything callable. */

	.global undecodable_cave_target
	.type undecodable_cave_target, @function
undecodable_cave_target:
	.global undecodable_cave_site
undecodable_cave_site:
	call qword ptr [rip + g_call_target_ptr]  /* FF 15 <disp32> -- 6 bytes */
	.global undecodable_cave_site_end
undecodable_cave_site_end:
	ret
	.size undecodable_cave_target, . - undecodable_cave_target

	.section .note.GNU-stack,"",@progbits
