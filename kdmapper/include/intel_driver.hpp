#pragma once
#include <Windows.h>
#include <string>
#include <iostream>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <type_traits>


#include "utils.hpp"
#include "nt.hpp"

namespace intel_driver
{
	constexpr ULONG32 ioctl1 = 0x80862007;
	// Exact-image independent-page symbols were unavailable or invalid. The
	// helper is torn down before a mapped image can be created or stopped.
	constexpr NTSTATUS independent_page_symbols_unavailable_status = static_cast<NTSTATUS>(0xC0E30003u);
	extern HANDLE hDevice;
	extern ULONG64 ntoskrnlAddr;

	bool ClearPiDDBCacheTable();
	bool ExAcquireResourceExclusiveLite(PVOID Resource, BOOLEAN wait);
	bool ExReleaseResourceLite(PVOID Resource);
	BOOLEAN RtlDeleteElementGenericTableAvl(PVOID Table, PVOID Buffer);
	PVOID RtlLookupElementGenericTableAvl(nt::PRTL_AVL_TABLE Table, PVOID Buffer);
	nt::PiDDBCacheEntry* LookupEntry(nt::PRTL_AVL_TABLE PiDDBCacheTable, ULONG timestamp, const wchar_t * name);
	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	NTSTATUS AcquireDebugPrivilege();

	uintptr_t FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

	bool ClearKernelHashBucketList();
	bool ClearWdFilterDriverList();

	bool IsRunning();
	// Called after the helper and ntoskrnl are available. The callback return
	// value is retained for source compatibility and is ignored.
	using symbol_provider = uint32_t(*)(void* context) noexcept;
	struct independent_page_rvas {
		uint32_t allocate = 0;
		uint32_t protect = 0;
		uint32_t free = 0;
	};
	namespace detail {
		enum class independent_page_api { allocate, protect, free };
		constexpr bool CompleteIndependentPageRvas(independent_page_rvas rvas) noexcept {
			return rvas.allocate && rvas.protect && rvas.free;
		}
		// No value means standalone callers may use the guarded signature path.
		// An engaged zero means strict callers must fail closed.
		constexpr std::optional<uint64_t> SelectIndependentPageTarget(
			bool exact_only, uint64_t image_base, independent_page_rvas rvas,
			independent_page_api api) noexcept {
			if (!exact_only) return std::nullopt;
			uint32_t rva = 0;
			switch (api) {
			case independent_page_api::allocate: rva = rvas.allocate; break;
			case independent_page_api::protect: rva = rvas.protect; break;
			case independent_page_api::free: rva = rvas.free; break;
			}
			if (!rva || !image_base ||
				image_base > (std::numeric_limits<uint64_t>::max)() - rva)
				return uint64_t{0};
			return image_base + rva;
		}
	}
	// A Load(provider, context) call requires all three addresses from a PDB
	// verified against the live ntoskrnl image. No signature fallback is used.
	bool ConfigureIndependentPageRvas(independent_page_rvas rvas);
	NTSTATUS Load();
	NTSTATUS Load(symbol_provider provider, void* context);
	NTSTATUS Unload();

	bool MemCopy(uint64_t destination, uint64_t source, uint64_t size);
	bool SetMemory(uint64_t address, uint32_t value, uint64_t size);
	bool GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address);
	uint64_t MapIoSpace(uint64_t physical_address, uint32_t size);
	bool UnmapIoSpace(uint64_t address, uint32_t size);
	bool ReadMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteMemory(uint64_t address, void* buffer, uint64_t size);
	bool WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size);
	/*added by herooyyy*/
	uint64_t MmAllocateIndependentPagesEx(uint32_t size);
	bool MmFreeIndependentPages(uint64_t address, uint32_t size);
	struct kernel_call_result {
		// Set only after the target call has returned to this process.
		bool target_invoked = false;
		// True if the trampoline was untouched or its original bytes were read back.
		bool trampoline_intact = true;
		bool trampoline_restored = false;
	};
	struct kernel_allocation_result {
		uint64_t address = 0;
		kernel_call_result call{};
	};
	kernel_allocation_result MmAllocateIndependentPagesExDetailed(uint32_t size);
	kernel_call_result MmFreeIndependentPagesDetailed(uint64_t address, uint32_t size);
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);
	
	uint64_t AllocatePool(nt::POOL_TYPE pool_type, uint64_t size);
	kernel_allocation_result AllocatePoolDetailed(nt::POOL_TYPE pool_type, uint64_t size);

	bool FreePool(uint64_t address);
	kernel_call_result FreePoolDetailed(uint64_t address);
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers();
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();
	std::mutex& KernelCallMutex();
	bool IsKernelCallTrampolineIntact();
	void MarkKernelCallTrampolineUnverified();
	bool RestoreKernelCallTrampoline(uint64_t address, const uint8_t* original, uint32_t size);
	namespace detail {
		template<typename Read, typename Write>
		bool RestoreKernelCallTrampolineWith(uint64_t address, const uint8_t* original,
			uint32_t size, Read read, Write write) {
			if (!address || !original || !size || size > 32) return false;
			uint8_t observed[32]{};
			auto restored = [&]() {
				return read(address, observed, size) && std::memcmp(observed, original, size) == 0;
			};
			if (restored()) return true;
			for (unsigned attempt = 0; attempt < 2; ++attempt) {
				(void)write(address, const_cast<uint8_t*>(original), size);
				if (restored()) return true;
			}
			return false;
		}
	}

	template<typename T, typename ...A>
	kernel_call_result CallKernelFunctionDetailed(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		kernel_call_result outcome{};
		std::lock_guard<std::mutex> call_lock(KernelCallMutex());
		if (!IsKernelCallTrampolineIntact()) {
			outcome.trampoline_intact = false;
			return outcome;
		}
		constexpr auto call_void = std::is_same_v<T, void>;

		//if count of arguments is >4 fail
		static_assert(sizeof...(A) <= 4, "CallKernelFunction: Too many arguments, CallKernelFunction only can be called with 4 or less arguments");

		if constexpr (!call_void) {
			if (!out_result)
				return outcome;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return outcome;

		// Setup function call
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			kdmLog(L"[-] Failed to load ntdll.dll" << std::endl); //never should happens
			return outcome;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom)
		{
			kdmLog(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return outcome;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		std::memcpy(&kernel_injected_jmp[2], &kernel_function_address, sizeof(kernel_function_address));

		static uint64_t kernel_NtAddAtom = 0;
		if (!kernel_NtAddAtom)
			kernel_NtAddAtom = GetKernelModuleExport(intel_driver::ntoskrnlAddr, "NtAddAtom");
		if (!kernel_NtAddAtom) {
			kdmLog(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return outcome;
		}
		constexpr uint8_t endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
		if (kernel_NtAddAtom > (std::numeric_limits<uint64_t>::max)() - (sizeof(endbr64) - 1))
			return outcome;
		uint8_t original_prefix[sizeof(endbr64)]{};
		if (!ReadMemory(kernel_NtAddAtom, original_prefix, sizeof(original_prefix)))
			return outcome;
		auto const has_landing_pad = std::memcmp(original_prefix, endbr64, sizeof(endbr64)) == 0;
		uint32_t const patch_offset = has_landing_pad ? static_cast<uint32_t>(sizeof(endbr64)) : 0;
		if (kernel_NtAddAtom > (std::numeric_limits<uint64_t>::max)() - patch_offset)
			return outcome;
		auto const patch_address = kernel_NtAddAtom + patch_offset;
		// The physical-write helper translates only the first page. Preserve an
		// existing IBT landing pad and apply this gate to the actual suffix write.
		if ((patch_address & 0xfff) > 0x1000 - sizeof(kernel_injected_jmp))
			return outcome;
		uint32_t const original_size = patch_offset + static_cast<uint32_t>(sizeof(kernel_injected_jmp));
		uint8_t original_kernel_function[sizeof(endbr64) + sizeof(kernel_injected_jmp)]{};

		if (!ReadMemory(kernel_NtAddAtom, original_kernel_function, original_size))
			return outcome;
		if (std::memcmp(original_kernel_function, original_prefix, sizeof(original_prefix)) != 0) {
			MarkKernelCallTrampolineUnverified();
			outcome.trampoline_intact = false;
			return outcome;
		}

		if (original_kernel_function[patch_offset] == kernel_injected_jmp[0] &&
			original_kernel_function[patch_offset + 1] == kernel_injected_jmp[1] &&
			original_kernel_function[original_size - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[original_size - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			kdmLog(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
			MarkKernelCallTrampolineUnverified();
			outcome.trampoline_intact = false;
			return outcome;
		}

		bool landing_pad_changed = false;
		auto restore_trampoline = [&]() {
			// Never write the preserved prefix, even during recovery. A suffix
			// restoration alone cannot establish that the complete entry is intact.
			auto const suffix_restored = RestoreKernelCallTrampoline(
				patch_address, original_kernel_function + patch_offset, sizeof(kernel_injected_jmp));
			uint8_t restored_bytes[sizeof(original_kernel_function)]{};
			auto const read_back = ReadMemory(kernel_NtAddAtom, restored_bytes, original_size);
			if (read_back && has_landing_pad &&
				std::memcmp(restored_bytes, original_prefix, sizeof(original_prefix)) != 0)
				landing_pad_changed = true;
			return suffix_restored && read_back && !landing_pad_changed &&
				std::memcmp(restored_bytes, original_kernel_function, original_size) == 0;
		};

		if (!WriteToReadOnlyMemory(patch_address, &kernel_injected_jmp, sizeof(kernel_injected_jmp))) {
			if (!restore_trampoline()) {
				MarkKernelCallTrampolineUnverified();
				outcome.trampoline_intact = false;
			}
			return outcome;
		}
		uint8_t expected_bytes[sizeof(original_kernel_function)]{};
		std::memcpy(expected_bytes, original_kernel_function, original_size);
		std::memcpy(expected_bytes + patch_offset, kernel_injected_jmp, sizeof(kernel_injected_jmp));
		uint8_t patched_bytes[sizeof(original_kernel_function)]{};
		auto const read_back = ReadMemory(kernel_NtAddAtom, patched_bytes, original_size);
		if (read_back && has_landing_pad &&
			std::memcmp(patched_bytes, original_prefix, sizeof(original_prefix)) != 0)
			landing_pad_changed = true;
		if (!read_back || std::memcmp(patched_bytes, expected_bytes, original_size) != 0) {
			if (!restore_trampoline()) {
				MarkKernelCallTrampolineUnverified();
				outcome.trampoline_intact = false;
			}
			return outcome;
		}

		// Call function
		if constexpr (!call_void) {
			using FunctionFn = T(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			*out_result = Function(arguments...);
		}
		else {
			using FunctionFn = void(__stdcall*)(A...);
			const auto Function = reinterpret_cast<FunctionFn>(NtAddAtom);

			Function(arguments...);
		}
		outcome.target_invoked = true;

		// A reported write success is insufficient: read back the exact original
		// bytes before any caller may use another kernel-call trampoline.
		outcome.trampoline_restored = restore_trampoline();
		if (!outcome.trampoline_restored) {
			MarkKernelCallTrampolineUnverified();
			outcome.trampoline_intact = false;
		}
		return outcome;
	}

	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		auto const result = CallKernelFunctionDetailed(out_result, kernel_function_address, arguments...);
		return result.target_invoked && result.trampoline_intact;
	}
}
