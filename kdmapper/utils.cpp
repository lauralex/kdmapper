#include "utils.hpp"
#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include <cstring>
#include <limits>

#include "nt.hpp"

std::wstring kdmUtils::GetFullTempPath() {
	wchar_t temp_directory[MAX_PATH + 1] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathW(sizeof(temp_directory) / 2, temp_directory);
	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH + 1) {
		kdmLog(L"[-] Failed to get temp path" << std::endl);
		return L"";
	}
	if (temp_directory[wcslen(temp_directory) - 1] == L'\\')
		temp_directory[wcslen(temp_directory) - 1] = 0x0;

	return std::wstring(temp_directory);
}

bool kdmUtils::ReadFileToMemory(const std::wstring& file_path, std::vector<BYTE>* out_buffer,
	size_t max_bytes) {
	if (!out_buffer)
		return false;
	out_buffer->clear();
	std::ifstream file_ifstream(file_path, std::ios::binary | std::ios::ate);

	if (!file_ifstream)
		return false;

	const std::streamoff length = file_ifstream.tellg();
	if (length <= 0 || static_cast<uint64_t>(length) > max_bytes ||
		static_cast<uint64_t>(length) > (std::numeric_limits<size_t>::max)() ||
		length > (std::numeric_limits<std::streamsize>::max)())
		return false;

	out_buffer->resize(static_cast<size_t>(length));
	file_ifstream.seekg(0, std::ios::beg);
	if (!file_ifstream.read(reinterpret_cast<char*>(out_buffer->data()), length)) {
		out_buffer->clear();
		return false;
	}
	char trailing = 0;
	if (file_ifstream.get(trailing) || !file_ifstream.eof()) {
		out_buffer->clear();
		return false;
	}
	return true;
}

bool kdmUtils::CreateFileFromMemory(const std::wstring& desired_file_path, const char* address, size_t size) {
	if (!address || !size || size > MAXDWORD) return false;
	HANDLE file = CreateFileW(desired_file_path.c_str(), GENERIC_WRITE, 0, nullptr,
		CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE) return false;
	DWORD written = 0;
	bool const written_all = WriteFile(file, address, static_cast<DWORD>(size), &written, nullptr) &&
		written == size;
	bool const complete = CloseHandle(file) && written_all;
	if (!complete) _wremove(desired_file_path.c_str());
	return complete;
}

uint64_t kdmUtils::GetKernelModuleAddress(const std::string& module_name) {
	void* buffer = nullptr;
	DWORD buffer_size = 0;
	DWORD allocated_size = 0;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, buffer_size, &buffer_size);

	for (unsigned attempt = 0; status == STATUS_INFO_LENGTH_MISMATCH && attempt < 4; ++attempt) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		buffer = nullptr;
		if (!buffer_size || buffer_size > 256 * 1024 * 1024)
			return 0;
		allocated_size = buffer_size;
		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (!buffer)
			return 0;
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemModuleInformation), buffer, allocated_size, &buffer_size);
	}

	if (!NT_SUCCESS(status)) {
		if (buffer != nullptr)
			VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	const auto modules = static_cast<nt::PRTL_PROCESS_MODULES>(buffer);
	if (!modules)
		return 0;
	constexpr size_t header_size = offsetof(nt::RTL_PROCESS_MODULES, Modules);
	if (allocated_size < header_size ||
		modules->NumberOfModules >
		(allocated_size - header_size) / sizeof(nt::RTL_PROCESS_MODULE_INFORMATION)) {
		VirtualFree(buffer, 0, MEM_RELEASE);
		return 0;
	}

	for (auto i = 0u; i < modules->NumberOfModules; ++i) {
		const auto& module = modules->Modules[i];
		if (module.OffsetToFileName >= sizeof(module.FullPathName) ||
			!memchr(module.FullPathName + module.OffsetToFileName, 0,
				sizeof(module.FullPathName) - module.OffsetToFileName)) {
			VirtualFree(buffer, 0, MEM_RELEASE);
			return 0;
		}
		const std::string current_module_name = std::string(
			reinterpret_cast<const char*>(module.FullPathName + module.OffsetToFileName));

		if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
		{
			const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

			VirtualFree(buffer, 0, MEM_RELEASE);
			return result;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}

BOOLEAN kdmUtils::bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == 0;
}

uintptr_t kdmUtils::FindPattern(uintptr_t dwAddress, uintptr_t dwLen, BYTE* bMask, const char* szMask) {
	if (!dwAddress || !bMask || !szMask) return 0;
	size_t const mask_len = strlen(szMask);
	if (!mask_len || dwLen < mask_len) return 0;
	uintptr_t const last = dwLen - mask_len;
	for (uintptr_t i = 0; i <= last; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (uintptr_t)(dwAddress + i);
	return 0;
}

PVOID kdmUtils::FindSection(const char* sectionName, uintptr_t modulePtr, PULONG size) {
	size_t namelength = strlen(sectionName);
	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(modulePtr + ((PIMAGE_DOS_HEADER)modulePtr)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, sectionName, namelength) == 0 &&
			namelength == strlen((char*)section->Name)) {
			if (!section->VirtualAddress) {
				return 0;
			}
			if (size) {
				*size = section->Misc.VirtualSize;
			}
			return (PVOID)(modulePtr + section->VirtualAddress);
		}
	}
	return 0;
}

std::wstring kdmUtils::GetCurrentAppFolder() {
	wchar_t buffer[1024];
	GetModuleFileNameW(NULL, buffer, 1024);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	return std::wstring(buffer).substr(0, pos);
}
