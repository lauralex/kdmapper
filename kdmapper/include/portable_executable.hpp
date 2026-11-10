#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <cstddef>

namespace portable_executable
{
	struct ImportFunctionInfo
	{
		std::string name;
		ULONG64* address;
	};

	struct ImportInfo
	{
		std::string module_name;
		std::vector<ImportFunctionInfo> function_datas;
	};

	using vec_sections = std::vector<IMAGE_SECTION_HEADER>;
	// Each target is an immutable, bounds-checked RVA. The relocation table in
	// the local image may itself be changed by an earlier relocation write.
	using vec_relocs = std::vector<ULONG32>;
	using vec_imports = std::vector<ImportInfo>;

	PIMAGE_NT_HEADERS64 GetNtHeaders(const void* image_base, size_t image_size);
	bool ValidateFileImage(const BYTE* data, size_t data_size, PIMAGE_NT_HEADERS64* headers);
	bool ValidateLoadConfig(const void* image_base, size_t image_size);
	bool GetRelocs(void* image_base, size_t image_size, vec_relocs* relocs);
	bool ApplyRelocations(void* image_base, size_t image_size, const vec_relocs& relocs, ULONG64 delta);
	bool GetImports(void* image_base, size_t image_size, vec_imports* imports);
}
