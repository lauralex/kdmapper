#include "kdmapper.hpp"
#include <Windows.h>
#include <iostream>

#include "utils.hpp"
#include "intel_driver.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"

// Fix cookie by @Jerem584
bool FixSecurityCookie(void* local_image, size_t image_size, ULONG64 kernel_image_base)
{
	auto headers = portable_executable::GetNtHeaders(local_image, image_size);
	if (!headers)
		return false;

	const auto& directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	auto load_config_directory = directory.VirtualAddress;
	if (!load_config_directory)
	{
		kdmLog(L"[+] Load config directory wasn't found, probably StackCookie not defined, fix cookie skipped" << std::endl);
		return true;
	}

	if (directory.Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(ULONGLONG) ||
		load_config_directory > image_size || directory.Size > image_size - load_config_directory)
		return false;
	auto load_config_struct = (PIMAGE_LOAD_CONFIG_DIRECTORY64)((uintptr_t)local_image + load_config_directory);
	auto stack_cookie = load_config_struct->SecurityCookie;
	if (!stack_cookie)
	{
		kdmLog(L"[+] StackCookie not defined, fix cookie skipped" << std::endl);
		return true; // as I said, it is not an error and we should allow that behavior
	}

	if (stack_cookie < kernel_image_base || stack_cookie - kernel_image_base > image_size ||
		sizeof(uintptr_t) > image_size - (stack_cookie - kernel_image_base))
		return false;
	stack_cookie = stack_cookie - (uintptr_t)kernel_image_base + (uintptr_t)local_image;

	if (*(uintptr_t*)(stack_cookie) != 0x2B992DDFA232) {
		kdmLog(L"[-] StackCookie already fixed!? this probably wrong" << std::endl);
		return false;
	}

	kdmLog(L"[+] Fixing stack cookie" << std::endl);

	auto new_cookie = 0x2B992DDFA232 ^ GetCurrentProcessId() ^ GetCurrentThreadId(); // here we don't really care about the value of stack cookie, it will still works and produce nice result
	if (new_cookie == 0x2B992DDFA232)
		new_cookie = 0x2B992DDFA233;

	*(uintptr_t*)(stack_cookie) = new_cookie; // the _security_cookie_complement will be init by the driver itself if they use crt
	return true;
}

bool ResolveImports(portable_executable::vec_imports imports) {
	for (const auto& current_import : imports) {
		ULONG64 Module = kdmUtils::GetKernelModuleAddress(current_import.module_name);
		if (!Module) {
#if !defined(DISABLE_OUTPUT)
			std::cout << "[-] Dependency " << current_import.module_name << " wasn't found" << std::endl;
#endif
			return false;
		}

		for (auto& current_function_data : current_import.function_datas) {
			ULONG64 function_address = intel_driver::GetKernelModuleExport(Module, current_function_data.name);

			if (!function_address) {
				//Lets try with ntoskrnl
				if (Module != intel_driver::ntoskrnlAddr) {
					function_address = intel_driver::GetKernelModuleExport(intel_driver::ntoskrnlAddr, current_function_data.name);
				}
				if (!function_address) {
#if !defined(DISABLE_OUTPUT)
					std::cout << "[-] Failed to resolve import " << current_function_data.name << " (" << current_import.module_name << ")" << std::endl;
#endif
					return false;
				}
			}

			*current_function_data.address = function_address;
		}
	}

	return true;
}

ULONG64 kdmapper::MapDriver(BYTE* data, size_t data_size, ULONG64 param1, ULONG64 param2, bool free, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, mapCallback callback, NTSTATUS* exitCode, kdmapper::map_result* outcome) {
	if (outcome) *outcome = {};
	PIMAGE_NT_HEADERS64 nt_headers = nullptr;
	if (!portable_executable::ValidateFileImage(data, data_size, &nt_headers)) {
		kdmLog(L"[-] Invalid or truncated PE image" << std::endl);
		return 0;
	}
	if (!intel_driver::IsKernelCallTrampolineIntact()) {
		if (outcome) outcome->trampoline_intact = false;
		return 0;
	}

	ULONG32 image_size = nt_headers->OptionalHeader.SizeOfImage;
	const size_t full_image_size = image_size;

	void* local_image_base = VirtualAlloc(nullptr, image_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!local_image_base)
		return 0;

	DWORD TotalVirtualHeaderSize = (IMAGE_FIRST_SECTION(nt_headers))->VirtualAddress;
	memcpy(local_image_base, data, nt_headers->OptionalHeader.SizeOfHeaders);
	const PIMAGE_SECTION_HEADER current_image_section = IMAGE_FIRST_SECTION(nt_headers);
	for (auto i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
		if ((current_image_section[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA) > 0 ||
			!current_image_section[i].SizeOfRawData)
			continue;
		auto local_section = reinterpret_cast<void*>(reinterpret_cast<ULONG64>(local_image_base) + current_image_section[i].VirtualAddress);
		memcpy(local_section, data + current_image_section[i].PointerToRawData, current_image_section[i].SizeOfRawData);
	}
	portable_executable::vec_relocs relocations;
	portable_executable::vec_imports imports;
	if (!portable_executable::ValidateLoadConfig(local_image_base, full_image_size) ||
		!portable_executable::GetRelocs(local_image_base, full_image_size, &relocations) ||
		!portable_executable::GetImports(local_image_base, full_image_size, &imports)) {
		kdmLog(L"[-] Invalid PE relocation, import, or load configuration data" << std::endl);
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}
	image_size = image_size - (destroyHeader ? TotalVirtualHeaderSize : 0);

	intel_driver::kernel_allocation_result allocation{};
	if (mode == AllocationMode::AllocateIndependentPages)
	{
		allocation = intel_driver::MmAllocateIndependentPagesExDetailed(image_size);
	}
	else { // AllocatePool by default
		allocation = intel_driver::AllocatePoolDetailed(nt::POOL_TYPE::NonPagedPool, image_size);
	}
	ULONG64 kernel_image_base = allocation.address;
	if (outcome) {
		outcome->trampoline_intact = allocation.call.trampoline_intact;
		outcome->image_retained = allocation.address != 0;
		outcome->image_base = allocation.address;
	}
	if (!allocation.call.trampoline_intact) {
		kdmLog(L"[-] Kernel call trampoline restoration is unverified after image allocation" << std::endl);
		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	if (!kernel_image_base) {
		kdmLog(L"[-] Failed to allocate remote image in kernel" << std::endl);

		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return 0;
	}

	do {
		kdmLog(L"[+] Image base has been allocated at 0x" << reinterpret_cast<void*>(kernel_image_base) << std::endl);

		ULONG64 realBase = kernel_image_base;
		if (destroyHeader) {
			kernel_image_base -= TotalVirtualHeaderSize;
			kdmLog(L"[+] Skipped 0x" << std::hex << TotalVirtualHeaderSize << L" bytes of PE Header" << std::endl);
		}
		if (relocations.empty() && kernel_image_base != nt_headers->OptionalHeader.ImageBase) {
			kdmLog(L"[-] Image has no usable relocations for its allocated base" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Resolve relocs and imports

		if (!portable_executable::ApplyRelocations(local_image_base, full_image_size,
			relocations, kernel_image_base - nt_headers->OptionalHeader.ImageBase)) {
			kdmLog(L"[-] Failed to apply validated relocations" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (!FixSecurityCookie(local_image_base, full_image_size, kernel_image_base ))
		{
			kdmLog(L"[-] Failed to fix cookie" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (!ResolveImports(imports)) {
			kdmLog(L"[-] Failed to resolve imports" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		// Write fixed image to kernel

		if (!intel_driver::WriteMemory(realBase, (PVOID)((uintptr_t)local_image_base + (destroyHeader ? TotalVirtualHeaderSize : 0)), image_size)) {
			kdmLog(L"[-] Failed to write local image to remote image" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		if (mode == AllocationMode::AllocateIndependentPages)
		{
			bool protection_ok = true;
			auto ProtectionToString = [](ULONG prot) -> const char* {
				switch (prot)
				{
				case PAGE_NOACCESS: return "NOACCESS";
				case PAGE_READONLY: return "READONLY";
				case PAGE_READWRITE: return "READWRITE";
				case PAGE_EXECUTE: return "EXECUTE";
				case PAGE_EXECUTE_READ: return "EXECUTE_READ";
				case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
				default: return "UNKNOWN";
				}
				};

			for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
				auto sec = &IMAGE_FIRST_SECTION(nt_headers)[i];
				std::wstring section_name;
				for (unsigned j = 0; j < sizeof(sec->Name) && sec->Name[j]; ++j)
					section_name.push_back(static_cast<wchar_t>(sec->Name[j]));
				uintptr_t secAddr = kernel_image_base + sec->VirtualAddress;
				uint32_t secSize = sec->Misc.VirtualSize;

				if (secSize <= 0) {
					kdmLog(L"[*] Skipping empty section: " << section_name << std::endl);
					continue;
				}

				ULONG prot = PAGE_READONLY;

				if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
					prot = (sec->Characteristics & IMAGE_SCN_MEM_WRITE) ?
						PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) {
					prot = PAGE_READWRITE;
				}
				else if (sec->Characteristics & IMAGE_SCN_MEM_READ) {
					prot = PAGE_READONLY;
				}

				kdmLog(L"[+] Setting protection for section: "
					<< section_name
					<< L" Base: 0x" << std::hex << secAddr
					<< L" Size: 0x" << secSize
					<< L" Prot: " << ProtectionToString(prot)
					<< std::dec << std::endl);

				if (!intel_driver::MmSetPageProtection(secAddr, secSize, prot)) {
					kdmLog(L"[-] Failed to set protection for section: " << section_name << std::endl);
					protection_ok = false;
					break;
				}
			}
			if (!protection_ok) {
				kernel_image_base = realBase;
				break;
			}
		}

		// Call driver entry point

		const ULONG64 address_of_entry_point = kernel_image_base + nt_headers->OptionalHeader.AddressOfEntryPoint;

		kdmLog(L"[<] Calling DriverEntry 0x" << reinterpret_cast<void*>(address_of_entry_point) << std::endl);

		if (callback) {
			if (!callback(&param1, &param2, realBase, image_size)) {
				kdmLog(L"[-] Callback returns false, failed!" << std::endl);
				kernel_image_base = realBase;
				break;
			}
		}

		NTSTATUS status = 0;
		auto const entry_call = intel_driver::CallKernelFunctionDetailed(&status,
			address_of_entry_point, (PassAllocationAddressAsFirstParam ? realBase : param1), param2);
		if (outcome) {
			outcome->entry_invoked = entry_call.target_invoked;
			outcome->trampoline_intact = entry_call.trampoline_intact;
		}
		if (entry_call.target_invoked && exitCode) *exitCode = status;
		if (!entry_call.trampoline_intact) {
			kdmLog(L"[-] Kernel call trampoline restoration is unverified; retaining mapped image" << std::endl);
			VirtualFree(local_image_base, 0, MEM_RELEASE);
			return 0;
		}
		if (!entry_call.target_invoked) {
			kdmLog(L"[-] Failed to call driver entry" << std::endl);
			kernel_image_base = realBase;
			break;
		}

		kdmLog(L"[+] DriverEntry returned 0x" << std::hex << status << std::endl);

		// Free memory
		if (free) {
			kdmLog(L"[+] Freeing memory" << std::endl);
			intel_driver::kernel_call_result release{};

			if (mode == AllocationMode::AllocateIndependentPages)
			{
				release = intel_driver::MmFreeIndependentPagesDetailed(realBase, image_size);
			}
			else {
				release = intel_driver::FreePoolDetailed(realBase);
			}
			bool const free_status = release.target_invoked && release.trampoline_intact;
			if (outcome) {
				outcome->trampoline_intact = release.trampoline_intact;
				outcome->image_retained = !free_status;
				outcome->image_release_call_completed = free_status;
			}

			if (free_status) {
				kdmLog(L"[+] Memory release call completed" << std::endl);
			}
			else {
				kdmLog(L"[-] WARNING: Memory release was not confirmed!" << std::endl);
			}
			if (!free_status) {
				VirtualFree(local_image_base, 0, MEM_RELEASE);
				return 0;
			}
		}



		VirtualFree(local_image_base, 0, MEM_RELEASE);
		return realBase;

	} while (false);


	VirtualFree(local_image_base, 0, MEM_RELEASE);
	if (!intel_driver::IsKernelCallTrampolineIntact()) {
		kdmLog(L"[-] Kernel call trampoline is unverified; retaining mapped image" << std::endl);
		if (outcome) {
			outcome->trampoline_intact = false;
			outcome->image_retained = true;
			outcome->image_base = kernel_image_base;
		}
		return 0;
	}

	kdmLog(L"[+] Freeing memory" << std::endl);
	intel_driver::kernel_call_result release{};

	if (mode == AllocationMode::AllocateIndependentPages)
	{
		release = intel_driver::MmFreeIndependentPagesDetailed(kernel_image_base, image_size);
	}
	else {
		release = intel_driver::FreePoolDetailed(kernel_image_base);
	}
	bool const free_status = release.target_invoked && release.trampoline_intact;
	if (outcome) {
		outcome->trampoline_intact = release.trampoline_intact;
		outcome->image_retained = !free_status;
		outcome->image_release_call_completed = free_status;
	}

	if (free_status) {
		kdmLog(L"[+] Memory release call completed" << std::endl);
	}
	else {
		kdmLog(L"[-] WARNING: Memory release was not confirmed!" << std::endl);
	}

	return 0;
}


