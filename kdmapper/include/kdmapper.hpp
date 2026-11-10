#pragma once

#include <Windows.h>
#include <cstddef>

namespace kdmapper
{
	enum class AllocationMode
	{
		AllocatePool,
		AllocateIndependentPages
	};

	typedef bool (*mapCallback)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize);

	// A failed entry call may have executed the driver before the temporary
	// kernel call trampoline could be restored. In that case the image must be
	// retained and no further trampoline call is safe in this process.
	struct map_result {
		bool entry_invoked = false;
		bool trampoline_intact = true;
		// True when an allocation is known and no completed release call exists.
		// A completed private free call is not independent proof of deallocation.
		bool image_retained = false;
		bool image_release_call_completed = false;
		ULONG64 image_base = 0;
	};

	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	ULONG64 MapDriver(BYTE* data, size_t data_size, ULONG64 param1 = 0, ULONG64 param2 = 0, bool free = false, bool destroyHeader = true, AllocationMode mode = AllocationMode::AllocatePool, bool PassAllocationAddressAsFirstParam = false, mapCallback callback = nullptr, NTSTATUS* exitCode = nullptr, map_result* outcome = nullptr);
}
