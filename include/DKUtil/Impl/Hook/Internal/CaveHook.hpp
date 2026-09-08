#pragma once

#if !defined(DKU_H_INTERNAL_IMPORTS)
#	error Incorrect DKUtil::Hook internal import order.
#endif

namespace DKUtil::Hook
{
	namespace detail
	{
		// Minimal x86-64 instruction-length decoder scoped to what a cave
		// hook's stolen ("restored") byte range can plausibly contain --
		// the register/memory-operand forms a compiler emits around a
		// RIP-relative global access. This is NOT a general disassembler:
		// anything outside the opcodes/prefixes below is refused rather
		// than guessed. See docs/linux-port/CAVE-HOOKS.md #5 for why the
		// naive memcpy replay this replaces is unsafe.
		//
		// ⚠ SCOPE OF "REFUSED RATHER THAN GUESSED". The ONE position-dependence
		// this decoder models is RIP-relative addressing, which it rewrites.
		// Every other operand -- stack- and frame-relative ones included
		// (mod=01/10 with base=rsp/rbp, and the SIB forms of the same) -- is
		// ACCEPTED and replayed byte for byte, with `RipDispOffset == -1`. That
		// is correct only under a precondition DKUtil neither checks nor can
		// see:
		//
		//   With kRestoreAfterEpilog / kRestoreBeforeEpilog, the caller's
		//   prolog+epilog pair MUST leave rsp (and rbp) holding exactly what
		//   the original site had, at the point the stolen bytes are replayed.
		//
		// Break that and a stolen `mov rax,[rsp+0x78]` silently loads a
		// DIFFERENT stack slot into a live register mid-function: no ERROR, no
		// refusal, and no test here can catch it, because the fault is in the
		// caller's prolog, not in these bytes. NCT's two restoreStolen caves are
		// exactly this shape (`48 8B 44 24 78` and `48 8B 6C 24 08`,
		// BG3_NativeCameraTweaks/src/Linux/LinuxLayout.h) and rely on the
		// balanced CaveProlog/CaveEpilog pair in that mod's Hooks.cpp.
		struct StolenInsnInfo
		{
			bool          Valid{ false };
			std::uint8_t  Length{ 0 };
			// Offset of a 4-byte RIP-relative displacement within the
			// instruction, or -1 when the instruction has no such operand.
			int RipDispOffset{ -1 };
		};

		[[nodiscard]] inline StolenInsnInfo DecodeStolenInsn(const OpCode* a_code, std::size_t a_avail) noexcept
		{
			StolenInsnInfo info{};
			std::size_t    i = 0;

			// Legacy prefixes this decoder understands (66/F2/F3 -- none of
			// them change ModRM/SIB parsing). Anything else that can appear
			// before an opcode (67 address-size override, segment overrides,
			// F0 lock) changes semantics this decoder does not model, so
			// refuse outright rather than mis-measure the instruction.
			while (i < a_avail) {
				const auto b = a_code[i];
				if (b == 0x66 || b == 0xF2 || b == 0xF3) {
					++i;
					continue;
				}
				if (b == 0x67 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 || b == 0xF0) {
					return info;  // unmodeled prefix: refuse
				}
				break;
			}

			// REX prefix (optional, at most one).
			if (i < a_avail && (a_code[i] & 0xF0) == 0x40) {
				++i;
			}

			if (i >= a_avail) {
				return info;
			}

			bool          hasImm8 = false;
			std::uint8_t  opcode = a_code[i++];
			if (opcode == 0x0F) {
				if (i >= a_avail) {
					return info;
				}
				const auto                       op2 = a_code[i++];
				static constexpr std::array<std::uint8_t, 11> kKnownTwoByte{
					0xB6, 0xB7,  // movzx r, r/m8 / r/m16
					0x10, 0x11,  // movup[sd]/movss/movsd (with 66/F2/F3 prefix)
					0x28, 0x29,  // movap[sd]
					0x6E, 0x6F,  // movd/movq / movdqa/movdqu
					0x7E, 0x7F,  // movd/movq / movdqa/movdqu (store forms)
					0xD6,        // movq (store)
				};
				if (std::ranges::find(kKnownTwoByte, op2) == kKnownTwoByte.end()) {
					return info;  // unmodeled two-byte opcode: refuse
				}
				// none of the above take an immediate
			} else if (opcode == 0x8B || opcode == 0x8D || opcode == 0x89 || opcode == 0x3B || opcode == 0x63) {
				// mov r,r/m | lea r,m | mov r/m,r | cmp r,r/m | movsxd r64,r/m32
				// (REX.W + 63 /r) -- same ModRM/SIB/disp shape as 0x8B, including
				// the RIP-relative disp32 relocation path; no immediate.
			} else if (opcode == 0x80 || opcode == 0xC6) {
				// grp1 r/m8,imm8 | mov r/m8,imm8
				hasImm8 = true;
			} else {
				return info;  // unmodeled opcode: refuse
			}

			// ModRM (every opcode above requires one).
			if (i >= a_avail) {
				return info;
			}
			const auto modrm = a_code[i++];
			const auto mod = static_cast<std::uint8_t>((modrm >> 6) & 0x3);
			const auto rm = static_cast<std::uint8_t>(modrm & 0x7);

			int ripOffset = -1;
			if (mod == 0b00 && rm == 0b101) {
				// RIP-relative: disp32 immediately follows ModRM, no SIB.
				ripOffset = static_cast<int>(i);
				if (i + 4 > a_avail) {
					return info;
				}
				i += 4;
			} else if (mod != 0b11 && rm == 0b100) {
				// SIB byte present.
				if (i >= a_avail) {
					return info;
				}
				const auto sib = a_code[i++];
				const auto base = static_cast<std::uint8_t>(sib & 0x7);
				if (mod == 0b00 && base == 0b101) {
					if (i + 4 > a_avail) {
						return info;
					}
					i += 4;  // disp32, no base register
				} else if (mod == 0b01) {
					if (i + 1 > a_avail) {
						return info;
					}
					i += 1;
				} else if (mod == 0b10) {
					if (i + 4 > a_avail) {
						return info;
					}
					i += 4;
				}
			} else if (mod == 0b01) {
				if (i + 1 > a_avail) {
					return info;
				}
				i += 1;
			} else if (mod == 0b10) {
				if (i + 4 > a_avail) {
					return info;
				}
				i += 4;
			}
			// mod == 0b11: register-direct, no displacement, no RIP operand.

			if (hasImm8) {
				if (i + 1 > a_avail) {
					return info;
				}
				i += 1;
			}

			if (i > (std::numeric_limits<std::uint8_t>::max)()) {
				return info;  // implausible for anything in our opcode set; guard the cast
			}

			info.Valid = true;
			info.Length = static_cast<std::uint8_t>(i);
			info.RipDispOffset = ripOffset;
			return info;
		}

		// Decodes every instruction across [a_bytes, a_bytes + a_size). If
		// every one decodes cleanly, returns a copy of those bytes with any
		// RIP-relative disp32 rewritten so it still resolves to the same
		// original absolute target from its new home at a_dstAddr. Returns
		// std::nullopt -- refusing the whole range -- if any instruction is
		// an encoding this decoder doesn't recognise, if the range ends
		// mid-instruction, or if a relocated RIP target no longer fits in
		// +/-2GB of its new site.
		[[nodiscard]] inline std::optional<std::vector<OpCode>> RelocateStolenBytes(
			const OpCode* a_bytes, std::size_t a_size,
			std::uintptr_t a_srcAddr, std::uintptr_t a_dstAddr) noexcept
		{
			std::vector<OpCode> out(a_bytes, a_bytes + a_size);
			std::size_t         offset = 0;

			while (offset < a_size) {
				const auto insn = DecodeStolenInsn(a_bytes + offset, a_size - offset);
				if (!insn.Valid || offset + insn.Length > a_size) {
					return std::nullopt;
				}

				if (insn.RipDispOffset >= 0) {
					std::int32_t disp = 0;
					std::memcpy(&disp, a_bytes + offset + insn.RipDispOffset, sizeof(disp));

					const auto absTarget = static_cast<std::intptr_t>(a_srcAddr + offset + insn.Length) + disp;
					const auto newEnd = static_cast<std::intptr_t>(a_dstAddr + offset + insn.Length);
					const auto newDispWide = absTarget - newEnd;

					if (newDispWide < (std::numeric_limits<std::int32_t>::min)() ||
						newDispWide > (std::numeric_limits<std::int32_t>::max)()) {
						return std::nullopt;  // trampoline landed too far from the original target
					}

					const auto newDisp = static_cast<std::int32_t>(newDispWide);
					std::memcpy(out.data() + offset + insn.RipDispOffset, &newDisp, sizeof(newDisp));
				}

				offset += insn.Length;
			}

			return out;
		}
	}  // namespace detail

	class CaveHookHandle : public HookHandle
	{
	public:
		// execution address, trampoline address, <cave low offset, cave high offset>
		// Null/skipped cave hook: an unresolved site from a partial site catalog.
		explicit CaveHookHandle(std::nullptr_t) noexcept :
			HookHandle(0, 0), Offset(0, 0), CaveSize(0), CaveEntry(0)
		{}

		CaveHookHandle(
			const std::uintptr_t a_address,
			const std::uintptr_t a_tramPtr,
			const offset_pair    a_offset) noexcept :
			HookHandle(a_address, a_tramPtr),
			Offset(a_offset), CaveSize(a_offset.second - a_offset.first), CaveEntry(Address + a_offset.first), CavePtr(Address + a_offset.first)
		{
			OldBytes.resize(CaveSize);
			CaveBuf.resize(CaveSize, NOP);
			std::memcpy(OldBytes.data(), AsPointer(CaveEntry), CaveSize);

			__DEBUG(
				"DKU_H: Cave capacity: {} bytes\n"
				"cave entry : {:X}\n"
				"tram entry : {:X}",
				CaveSize, CaveEntry, TramEntry);
		}

		void Enable() noexcept override
		{
			if (!Address) {
				return;  // skipped (unresolved) cave hook
			}
			WriteData(CavePtr, CaveBuf.data(), CaveSize, false);
			CavePtr += CaveSize;
			__DEBUG("DKU_H: Enabled cave hook @ {:X}", CaveEntry);
		}

		void Disable() noexcept override
		{
			if (!Address) {
				return;
			}
			WriteData(CavePtr - CaveSize, OldBytes.data(), CaveSize, false);
			CavePtr -= CaveSize;
			__DEBUG("DKU_H: Disabled cave hook @ {:X}", CaveEntry);
		}

		const offset_pair    Offset;
		const std::size_t    CaveSize;
		const std::uintptr_t CaveEntry;
		std::uintptr_t       CavePtr{ 0x0 };
		std::vector<OpCode>  OldBytes{};
		std::vector<OpCode>  CaveBuf{};
	};

	namespace detail
	{
		// Replays a_handle->OldBytes into the trampoline at its current
		// TramPtr, relocating any RIP-relative displacement inside them
		// instead of the naive memcpy this replaces (see CAVE-HOOKS.md #5).
		// Returns false -- writing nothing -- if any instruction in the
		// stolen range can't be proven safe to relocate; the caller must
		// refuse the whole hook rather than install a mis-relocated one.
		//
		// PRECONDITION (unchecked, see DecodeStolenInsn's header): stack- and
		// frame-relative operands are replayed VERBATIM. The caller's epilog
		// must therefore restore rsp/rbp to exactly their values at the
		// original site before these bytes execute.
		[[nodiscard]] inline bool WriteRelocatedStolenBytes(CaveHookHandle* a_handle) noexcept
		{
			auto relocated = RelocateStolenBytes(
				a_handle->OldBytes.data(), a_handle->CaveSize, a_handle->CaveEntry, a_handle->TramPtr);
			if (!relocated) {
				ERROR(
					"DKU_H: cave hook stolen bytes @ {:X} (size {}) contain an instruction this fork "
					"cannot prove is safe to relocate -- an unrecognised encoding, or a RIP-relative "
					"target that no longer fits +/-2GB of the trampoline. Refusing the hook rather "
					"than silently computing a wrong address; see docs/linux-port/CAVE-HOOKS.md #5.",
					a_handle->CaveEntry, a_handle->CaveSize);
				return false;
			}
			a_handle->Write(relocated->data(), relocated->size());
			return true;
		}
	}  // namespace detail

	/** \brief Branch to hook function in the body of execution from target function.
	 * \param a_offset : Offset pairs for <beginning, end> of cave entry from the head of function
	 * \param a_address : Memory address of the BEGINNING of target function
	 * \param a_funcInfo : FUNC_INFO or RT_INFO wrapper of hook function
	 * \param a_prolog : Prolog patch before detouring to hook function
	 * \param a_epilog : Epilog patch after returning from hook function
	 * \param a_flag : Specifies operation on cave hook
	 * \return CaveHookHandle
	 */
	[[nodiscard]] inline auto AddCaveHook(
		const std::uintptr_t         a_address,
		const offset_pair            a_offset,
		const FuncInfo               a_funcInfo,
		const unpacked_data          a_prolog = std::make_pair(nullptr, 0),
		const unpacked_data          a_epilog = std::make_pair(nullptr, 0),
		model::enumeration<HookFlag> a_flag = HookFlag::kSkipNOP) noexcept
	{
#if !defined(_WIN32)
		if (!a_address) {
			// Unresolved site from a partial catalog: skip rather than patch 0.
			return std::make_unique<CaveHookHandle>(nullptr);
		}
#endif
		if (a_offset.second - a_offset.first == 5) {
			a_flag.reset(HookFlag::kSkipNOP);
		}

		JmpRel  asmDetour;  // cave -> tram
		JmpRel  asmReturn;  // tram -> cave
		SubRsp  asmSub;
		AddRsp  asmAdd;
		CallRip asmBranch;

		// trampoline layout
		// [qword imm64] <- tram entry after this
		// [stolen] <- kRestoreBeforeProlog
		// [prolog] <- cave detour entry
		// [stolen] <- kRestoreAfterProlog
		// [alloc stack]
		// [call qword ptr [rip + disp]]
		// [dealloc stack]
		// [stolen] <- kRestoreBeforeEpilog
		// [epilog]
		// [stolen] <- kRestoreAfterEpilog
		// [jmp rel32]
		auto tramPtr = TRAM_ALLOC(0);

		// tram entry
		WriteImm(tramPtr, a_funcInfo.address(), true);
		tramPtr += sizeof(a_funcInfo.address());
		__DEBUG(
			"DKU_H: Detouring...\n"
			"from : {}.{:X}\n"
			"to   : {} @ {}.{:X}",
			GetModuleName(), a_address + a_offset.first, a_funcInfo.name(), PROJECT_NAME, a_funcInfo.address());

		auto handle = std::make_unique<CaveHookHandle>(a_address, tramPtr, a_offset);

		std::ptrdiff_t disp = handle->TramPtr - handle->CavePtr - sizeof(asmDetour);
		assert_trampoline_range(disp);

		asmDetour.Disp = static_cast<Disp32>(disp);
		AsMemCpy(handle->CaveBuf.data(), asmDetour);

		if (a_flag.any(HookFlag::kRestoreBeforeProlog)) {
			if (!detail::WriteRelocatedStolenBytes(handle.get())) {
				return std::make_unique<CaveHookHandle>(nullptr);
			}
			asmBranch.Disp -= static_cast<Disp32>(handle->CaveSize);

			a_flag.reset(HookFlag::kRestoreBeforeProlog);
		}

		if (a_prolog.first && a_prolog.second) {
			handle->Write(a_prolog.first, a_prolog.second);
			asmBranch.Disp -= static_cast<Disp32>(a_prolog.second);
		}

		if (a_flag.any(HookFlag::kRestoreAfterProlog)) {
			if (!detail::WriteRelocatedStolenBytes(handle.get())) {
				return std::make_unique<CaveHookHandle>(nullptr);
			}
			asmBranch.Disp -= static_cast<Disp32>(handle->CaveSize);

			a_flag.reset(HookFlag::kRestoreBeforeEpilog, HookFlag::kRestoreAfterEpilog);
		}

		// alloc stack space
		asmSub.Size = ASM_STACK_ALLOC_SIZE;
		asmAdd.Size = ASM_STACK_ALLOC_SIZE;

		handle->Write(asmSub);
		asmBranch.Disp -= static_cast<Disp32>(sizeof(asmSub));

		// write call
		asmBranch.Disp -= static_cast<Disp32>(sizeof(Imm64));
		asmBranch.Disp -= static_cast<Disp32>(sizeof(asmBranch));
		handle->Write(asmBranch);

		// dealloc stack space
		handle->Write(asmAdd);

		if (a_flag.any(HookFlag::kRestoreBeforeEpilog)) {
			if (!detail::WriteRelocatedStolenBytes(handle.get())) {
				return std::make_unique<CaveHookHandle>(nullptr);
			}
			a_flag.reset(HookFlag::kRestoreAfterEpilog);
		}

		if (a_epilog.first && a_epilog.second) {
			handle->Write(a_epilog.first, a_epilog.second);
		}

		if (a_flag.any(HookFlag::kRestoreAfterEpilog)) {
			if (!detail::WriteRelocatedStolenBytes(handle.get())) {
				return std::make_unique<CaveHookHandle>(nullptr);
			}
		}

		if (a_flag.any(HookFlag::kSkipNOP)) {
			asmReturn.Disp = static_cast<Disp32>(handle->Address + handle->Offset.second - handle->TramPtr - sizeof(asmReturn));
		} else {
			asmReturn.Disp = static_cast<Disp32>(handle->CavePtr + sizeof(asmDetour) - handle->TramPtr - sizeof(asmReturn));
		}

		handle->Write(asmReturn);

		return std::move(handle);
	}
}  // namespace DKUtil::Hook
