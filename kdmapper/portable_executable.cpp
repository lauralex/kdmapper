#include "portable_executable.hpp"

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <utility>

namespace {
	bool within(uint64_t offset, uint64_t length, uint64_t size) {
		return offset <= size && length <= size - offset;
	}

	bool directory_bounds(const IMAGE_NT_HEADERS64* headers, size_t image_size,
		unsigned index, size_t minimum_size, DWORD* rva, DWORD* size) {
		if (headers->OptionalHeader.NumberOfRvaAndSizes <= index)
			return false;
		const auto& directory = headers->OptionalHeader.DataDirectory[index];
		*rva = directory.VirtualAddress;
		*size = directory.Size;
		if (!directory.VirtualAddress && !directory.Size)
			return true;
		return directory.VirtualAddress != 0 && directory.Size >= minimum_size &&
			within(directory.VirtualAddress, directory.Size, image_size);
	}

	bool terminated_string(const BYTE* base, size_t image_size, uint64_t rva) {
		if (!within(rva, 1, image_size))
			return false;
		return memchr(base + rva, 0, image_size - static_cast<size_t>(rva)) != nullptr;
	}
}

PIMAGE_NT_HEADERS64 portable_executable::GetNtHeaders(const void* image_base, size_t image_size) {
	if (!image_base || image_size < sizeof(IMAGE_DOS_HEADER))
		return nullptr;
	const auto* base = static_cast<const BYTE*>(image_base);
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(IMAGE_DOS_HEADER))
		return nullptr;
	const size_t nt_offset = static_cast<size_t>(dos->e_lfanew);
	if (!within(nt_offset, sizeof(IMAGE_NT_HEADERS64), image_size))
		return nullptr;
	const auto* headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + nt_offset);
	if (headers->Signature != IMAGE_NT_SIGNATURE ||
		headers->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64) ||
		!within(nt_offset + offsetof(IMAGE_NT_HEADERS64, OptionalHeader),
			headers->FileHeader.SizeOfOptionalHeader, image_size))
		return nullptr;
	return const_cast<PIMAGE_NT_HEADERS64>(headers);
}

bool portable_executable::ValidateFileImage(const BYTE* data, size_t data_size,
	PIMAGE_NT_HEADERS64* result) {
	if (result) *result = nullptr;
	if (!result)
		return false;
	auto* headers = GetNtHeaders(data, data_size);
	if (!headers || headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
		headers->OptionalHeader.NumberOfRvaAndSizes < IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
		!headers->FileHeader.NumberOfSections)
		return false;

	const auto& optional = headers->OptionalHeader;
	const uint64_t image_size = optional.SizeOfImage;
	const uint64_t headers_size = optional.SizeOfHeaders;
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
	const uint64_t section_offset = static_cast<uint64_t>(dos->e_lfanew) +
		offsetof(IMAGE_NT_HEADERS64, OptionalHeader) + headers->FileHeader.SizeOfOptionalHeader;
	const uint64_t section_bytes = static_cast<uint64_t>(headers->FileHeader.NumberOfSections) *
		sizeof(IMAGE_SECTION_HEADER);
	if (!image_size || image_size > 512ull * 1024 * 1024 ||
		optional.Subsystem != IMAGE_SUBSYSTEM_NATIVE || !headers_size || headers_size > image_size ||
		!within(0, headers_size, data_size) ||
		!within(section_offset, section_bytes, headers_size) ||
		!within(section_offset, section_bytes, data_size))
		return false;

	const auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(data + section_offset);
	const uint64_t first_section = sections[0].VirtualAddress;
	if (first_section < headers_size || first_section >= image_size ||
		!within(optional.AddressOfEntryPoint, 1, image_size) ||
		optional.AddressOfEntryPoint < first_section)
		return false;
	bool executable_entry = false;
	uint64_t previous_end = first_section;
	for (unsigned i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		const auto& section = sections[i];
		const uint64_t extent = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
		if (section.VirtualAddress < first_section ||
			section.VirtualAddress < previous_end ||
			!within(section.VirtualAddress, extent, image_size))
			return false;
		previous_end = section.VirtualAddress + extent;
		if (section.SizeOfRawData &&
			(section.PointerToRawData < headers_size ||
				!within(section.PointerToRawData, section.SizeOfRawData, data_size)))
			return false;
		if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
			optional.AddressOfEntryPoint >= section.VirtualAddress &&
			optional.AddressOfEntryPoint < section.VirtualAddress + extent)
			executable_entry = true;
	}
	if (!executable_entry)
		return false;

	DWORD rva = 0, size = 0;
	if (!directory_bounds(headers, image_size, IMAGE_DIRECTORY_ENTRY_BASERELOC,
		sizeof(IMAGE_BASE_RELOCATION), &rva, &size) ||
		!directory_bounds(headers, image_size, IMAGE_DIRECTORY_ENTRY_IMPORT,
		sizeof(IMAGE_IMPORT_DESCRIPTOR), &rva, &size) ||
		!directory_bounds(headers, image_size, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
		offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(ULONGLONG),
		&rva, &size))
		return false;
	*result = headers;
	return true;
}

bool portable_executable::ValidateLoadConfig(const void* image_base, size_t image_size) {
	const auto* headers = GetNtHeaders(image_base, image_size);
	if (!headers)
		return false;
	DWORD rva = 0, size = 0;
	if (!directory_bounds(headers, image_size, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
		offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie) + sizeof(ULONGLONG),
		&rva, &size))
		return false;
	if (!rva)
		return true;
	const auto* config = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY64*>(
		static_cast<const BYTE*>(image_base) + rva);
	const uint64_t cookie_va = config->SecurityCookie;
	const uint64_t preferred_base = headers->OptionalHeader.ImageBase;
	return !cookie_va || (cookie_va >= preferred_base &&
		within(cookie_va - preferred_base, sizeof(ULONGLONG), image_size));
}

bool portable_executable::GetRelocs(void* image_base, size_t image_size, vec_relocs* result) {
	if (!result)
		return false;
	result->clear();
	const auto* headers = GetNtHeaders(image_base, image_size);
	if (!headers)
		return false;
	DWORD rva = 0, size = 0;
	if (!directory_bounds(headers, image_size, IMAGE_DIRECTORY_ENTRY_BASERELOC,
		sizeof(IMAGE_BASE_RELOCATION), &rva, &size))
		return false;
	if (!rva)
		return true;
	auto* base = static_cast<BYTE*>(image_base);
	uint64_t position = rva;
	const uint64_t end = position + size;
	while (position < end) {
		if (!within(position, sizeof(IMAGE_BASE_RELOCATION), end))
			return false;
		auto* block = reinterpret_cast<PIMAGE_BASE_RELOCATION>(base + position);
		if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
			(block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) % sizeof(USHORT) ||
			!within(position, block->SizeOfBlock, end) ||
			!within(block->VirtualAddress, 1, image_size))
			return false;
		const auto* items = reinterpret_cast<const USHORT*>(
			base + position + sizeof(IMAGE_BASE_RELOCATION));
		const ULONG32 count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
		for (ULONG32 i = 0; i < count; ++i) {
			const USHORT type = items[i] >> 12;
			const USHORT offset = items[i] & 0xFFF;
			if (type != IMAGE_REL_BASED_ABSOLUTE &&
				(type != IMAGE_REL_BASED_DIR64 ||
					!within(static_cast<uint64_t>(block->VirtualAddress) + offset,
						sizeof(ULONG64), image_size)))
				return false;
			if (type == IMAGE_REL_BASED_DIR64)
				result->push_back(block->VirtualAddress + offset);
		}
		position += block->SizeOfBlock;
	}
	(std::sort)(result->begin(), result->end());
	for (size_t i = 1; i < result->size(); ++i)
		if ((*result)[i] - (*result)[i - 1] < sizeof(ULONG64))
			return false;
	return true;
}

bool portable_executable::ApplyRelocations(void* image_base, size_t image_size,
	const vec_relocs& relocs, ULONG64 delta) {
	if (!image_base)
		return false;
	for (const auto rva : relocs)
		if (!within(rva, sizeof(ULONG64), image_size))
			return false;
	auto* base = static_cast<BYTE*>(image_base);
	for (const auto rva : relocs) {
		ULONG64 value = 0;
		memcpy(&value, base + rva, sizeof(value));
		value += delta;
		memcpy(base + rva, &value, sizeof(value));
	}
	return true;
}

bool portable_executable::GetImports(void* image_base, size_t image_size, vec_imports* result) {
	if (!result)
		return false;
	result->clear();
	const auto* headers = GetNtHeaders(image_base, image_size);
	if (!headers)
		return false;
	DWORD rva = 0, size = 0;
	if (!directory_bounds(headers, image_size, IMAGE_DIRECTORY_ENTRY_IMPORT,
		sizeof(IMAGE_IMPORT_DESCRIPTOR), &rva, &size))
		return false;
	if (!rva)
		return true;
	auto* base = static_cast<BYTE*>(image_base);
	const size_t descriptor_count = size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	bool terminated = false;
	for (size_t i = 0; i < descriptor_count; ++i) {
		const auto* descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
			base + rva + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
		const IMAGE_IMPORT_DESCRIPTOR empty{};
		if (!memcmp(descriptor, &empty, sizeof(empty))) {
			terminated = true;
			break;
		}
		if (!descriptor->FirstThunk || !descriptor->Name ||
			!terminated_string(base, image_size, descriptor->Name))
			return false;
		const uint64_t source_rva = descriptor->OriginalFirstThunk ?
			descriptor->OriginalFirstThunk : descriptor->FirstThunk;
		const uint64_t destination_rva = descriptor->FirstThunk;
		if (!within(source_rva, sizeof(IMAGE_THUNK_DATA64), image_size) ||
			!within(destination_rva, sizeof(IMAGE_THUNK_DATA64), image_size))
			return false;
		ImportInfo info{};
		info.module_name = reinterpret_cast<const char*>(base + descriptor->Name);
		const size_t source_capacity = (image_size - static_cast<size_t>(source_rva)) /
			sizeof(IMAGE_THUNK_DATA64);
		const size_t destination_capacity = (image_size - static_cast<size_t>(destination_rva)) /
			sizeof(IMAGE_THUNK_DATA64);
		const size_t thunk_count = (std::min)(source_capacity, destination_capacity);
		bool thunk_terminated = false;
		for (size_t j = 0; j < thunk_count; ++j) {
			const auto* source = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
				base + source_rva + j * sizeof(IMAGE_THUNK_DATA64));
			if (!source->u1.AddressOfData) {
				thunk_terminated = true;
				break;
			}
			if (IMAGE_SNAP_BY_ORDINAL64(source->u1.Ordinal))
				return false;
			const uint64_t name_rva = source->u1.AddressOfData;
			const uint64_t name_offset = name_rva + offsetof(IMAGE_IMPORT_BY_NAME, Name);
			if (name_offset < name_rva || !terminated_string(base, image_size, name_offset))
				return false;
			ImportFunctionInfo function{};
			function.name = reinterpret_cast<const char*>(base + name_offset);
			auto* destination = reinterpret_cast<PIMAGE_THUNK_DATA64>(
				base + destination_rva + j * sizeof(IMAGE_THUNK_DATA64));
			function.address = &destination->u1.Function;
			info.function_datas.push_back(std::move(function));
		}
		if (!thunk_terminated)
			return false;
		result->push_back(std::move(info));
	}
	return terminated;
}
