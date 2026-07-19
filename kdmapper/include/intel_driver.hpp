#pragma once
#include <Windows.h>
#include <string>
#include <iostream>


#include "utils.hpp"
#include "nt.hpp"

namespace intel_driver
{
	constexpr ULONG32 ioctl1 = 0x80862007;
	inline constexpr char upstream_revision[] =
		"280f65733d6469cfdae9dff76f24793d90f1f672";
	inline constexpr char nebula_integration_revision[] = "2026-07-19.1";
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
	NTSTATUS Load();
	NTSTATUS Unload();

	// Compatibility entry point for embedders that still keep the mapper
	// device handle in their own operation context.  Upstream now owns the
	// handle globally, so callers should use this instead of interpreting an
	// NTSTATUS as a HANDLE.
	inline HANDLE LoadDevice(NTSTATUS* load_status = nullptr) {
		auto status = Load();
		if (NT_SUCCESS(status) &&
			(!hDevice || hDevice == INVALID_HANDLE_VALUE)) {
			Unload();
			status = STATUS_INVALID_HANDLE;
		}
		if (load_status)
			*load_status = status;
		return NT_SUCCESS(status) ? hDevice : INVALID_HANDLE_VALUE;
	}

	inline bool IsActiveHandle(HANDLE device_handle) {
		return device_handle && device_handle != INVALID_HANDLE_VALUE &&
			device_handle == hDevice;
	}

	inline bool Unload(HANDLE device_handle, NTSTATUS* unload_status) {
		auto status = STATUS_INVALID_HANDLE;
		if (IsActiveHandle(device_handle))
			status = Unload();
		if (unload_status)
			*unload_status = status;
		return NT_SUCCESS(status);
	}

	inline bool Unload(HANDLE device_handle) {
		return Unload(device_handle, nullptr);
	}

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
	BOOLEAN MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect);
	
	uint64_t AllocatePool(nt::POOL_TYPE pool_type, uint64_t size);

	bool FreePool(uint64_t address);
	uint64_t GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name);
	bool ClearMmUnloadedDrivers();
	std::wstring GetDriverNameW();
	std::wstring GetDriverPath();

	// Legacy-handle adapters keep existing library consumers source-compatible
	// with the upstream global-device API while rejecting stale handles.
	inline bool ReadMemory(HANDLE device_handle, uint64_t address, void* buffer,
		uint64_t size) {
		return IsActiveHandle(device_handle) && ReadMemory(address, buffer, size);
	}

	inline bool WriteMemory(HANDLE device_handle, uint64_t address, void* buffer,
		uint64_t size) {
		return IsActiveHandle(device_handle) && WriteMemory(address, buffer, size);
	}

	inline uint64_t MmAllocateIndependentPagesEx(HANDLE device_handle,
		uint32_t size) {
		return IsActiveHandle(device_handle) ? MmAllocateIndependentPagesEx(size) : 0;
	}

	inline bool MmFreeIndependentPages(HANDLE device_handle, uint64_t address,
		uint32_t size) {
		return IsActiveHandle(device_handle) &&
			MmFreeIndependentPages(address, size);
	}

	inline BOOLEAN MmSetPageProtection(HANDLE device_handle, uint64_t address,
		uint32_t size, ULONG new_protect) {
		return IsActiveHandle(device_handle) ?
			MmSetPageProtection(address, size, new_protect) : FALSE;
	}

	inline uint64_t AllocatePool(HANDLE device_handle, nt::POOL_TYPE pool_type,
		uint64_t size) {
		return IsActiveHandle(device_handle) ? AllocatePool(pool_type, size) : 0;
	}

	inline bool FreePool(HANDLE device_handle, uint64_t address) {
		return IsActiveHandle(device_handle) && FreePool(address);
	}

	inline uint64_t GetKernelModuleExport(HANDLE device_handle,
		uint64_t kernel_module_base, const std::string& function_name) {
		return IsActiveHandle(device_handle) ?
			GetKernelModuleExport(kernel_module_base, function_name) : 0;
	}

	template<typename T, typename ...A>
	bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments) {
		constexpr auto call_void = std::is_same_v<T, void>;

		//if count of arguments is >4 fail
		static_assert(sizeof...(A) <= 4, "CallKernelFunction: Too many arguments, CallKernelFunction only can be called with 4 or less arguments");

		if constexpr (!call_void) {
			if (!out_result)
				return false;
		}
		else {
			UNREFERENCED_PARAMETER(out_result);
		}

		if (!kernel_function_address)
			return false;

		// Setup function call
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == 0) {
			kdmLog(L"[-] Failed to load ntdll.dll" << std::endl); //never should happens
			return false;
		}

		const auto NtAddAtom = reinterpret_cast<void*>(GetProcAddress(ntdll, "NtAddAtom"));
		if (!NtAddAtom)
		{
			kdmLog(L"[-] Failed to get export ntdll.NtAddAtom" << std::endl);
			return false;
		}

		uint8_t kernel_injected_jmp[] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
		uint8_t original_kernel_function[sizeof(kernel_injected_jmp)];
		*(uint64_t*)&kernel_injected_jmp[2] = kernel_function_address;

		static uint64_t kernel_NtAddAtom = GetKernelModuleExport(intel_driver::ntoskrnlAddr, "NtAddAtom");
		if (!kernel_NtAddAtom) {
			kdmLog(L"[-] Failed to get export ntoskrnl.NtAddAtom" << std::endl);
			return false;
		}

		if (!ReadMemory(kernel_NtAddAtom, &original_kernel_function, sizeof(kernel_injected_jmp)))
			return false;

		if (original_kernel_function[0] == kernel_injected_jmp[0] &&
			original_kernel_function[1] == kernel_injected_jmp[1] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 2] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 2] &&
			original_kernel_function[sizeof(kernel_injected_jmp) - 1] == kernel_injected_jmp[sizeof(kernel_injected_jmp) - 1]) {
			kdmLog(L"[-] FAILED!: The code was already hooked!! another instance of kdmapper running?!" << std::endl);
			return false;
		}

		// Overwrite the pointer with kernel_function_address
		if (!WriteToReadOnlyMemory(kernel_NtAddAtom, &kernel_injected_jmp, sizeof(kernel_injected_jmp)))
			return false;

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

		// Restore the pointer/jmp
		return WriteToReadOnlyMemory(kernel_NtAddAtom, original_kernel_function, sizeof(kernel_injected_jmp));
	}

	template<typename T, typename ...A>
	bool CallKernelFunction(HANDLE device_handle, T* out_result,
		uint64_t kernel_function_address, const A ...arguments) {
		return IsActiveHandle(device_handle) &&
			CallKernelFunction(out_result, kernel_function_address, arguments...);
	}
}
