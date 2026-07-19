#pragma once

#include <Windows.h>

namespace kdmapper
{
	enum class AllocationMode
	{
		AllocatePool,
		AllocateIndependentPages
	};

	typedef bool (*mapCallback)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize);

	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	ULONG64 MapDriver(BYTE* data, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, AllocationMode mode = AllocationMode::AllocatePool, bool PassAllocationAddressAsFirstParam = false, mapCallback callback = nullptr, NTSTATUS* exitCode = nullptr);

	// Compatibility overload for consumers written against the pre-refactor
	// library API.  The implementation validates that the supplied handle is
	// the active upstream-owned mapper device before forwarding.
	ULONG64 MapDriver(HANDLE device_handle, BYTE* data, ULONG64 param1 = 0,
		ULONG64 param2 = 0, bool free = false, bool destroyHeader = true,
		AllocationMode mode = AllocationMode::AllocatePool,
		bool PassAllocationAddressAsFirstParam = false,
		mapCallback callback = nullptr, NTSTATUS* exitCode = nullptr);
}
