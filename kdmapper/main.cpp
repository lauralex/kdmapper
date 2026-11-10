#ifndef KDLIBMODE

#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <TlHelp32.h>

#include "kdmapper.hpp"
#include "utils.hpp"
#include "intel_driver.hpp"
#include "portable_executable.hpp"

#ifdef PDB_OFFSETS
#include "KDSymbolsHandler.h"
#endif

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		kdmLog(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		kdmLog(L"[!!] Crash" << std::endl);

	if (intel_driver::hDevice)
		kdmLog(L"[!!] Helper state is unknown after the crash; leaving it available for inspection" << std::endl);

	return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize) {
	UNREFERENCED_PARAMETER(param1);
	UNREFERENCED_PARAMETER(param2);
	UNREFERENCED_PARAMETER(allocationPtr);
	UNREFERENCED_PARAMETER(allocationSize);
	kdmLog("[+] Callback example called" << std::endl);
	
	/*
	This callback occurs before call driver entry and
	can be useful to pass more customized params in 
	the last step of the mapping procedure since you 
	know now the mapping address and other things
	*/
	return true;
}

DWORD getParentProcess()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != 0) CloseHandle(hSnapshot);
	}
	return ppid;
}

//Help people that don't understand how to open a console
void PauseIfParentIsExplorer() {
	DWORD explorerPid = 0;
	GetWindowThreadProcessId(GetShellWindow(), &explorerPid);
	DWORD parentPid = getParentProcess();
	if (parentPid == explorerPid) {
		kdmLog(L"[+] Pausing to allow for debugging" << std::endl);
		kdmLog(L"[+] Press enter to close" << std::endl);
		std::cin.get();
	}
}

void help() {
	kdmLog(L"\r\n\r\n[!] Incorrect Usage!" << std::endl);
	kdmLog(L"[+] Usage: kdmapper.exe [--free][--indPages][--PassAllocationPtr][--copy-header]");

#ifdef PDB_OFFSETS
	kdmLog(L"[--dontUpdateOffsets [--offsetsPath \"FilePath\"]]"); 
#endif
	
	kdmLog(L" driver" << std::endl);

	PauseIfParentIsExplorer();
}

int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	bool free = paramExists(argc, argv, L"free") > 0;
	bool indPagesMode = paramExists(argc, argv, L"indPages") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = paramExists(argc, argv, L"copy-header") > 0;

	if (free) {
		kdmLog(L"[+] Free memory after driver execution enabled" << std::endl);
	}

	if (indPagesMode) {
		kdmLog(L"[+] Allocate Independent Pages mode enabled" << std::endl);
	}

	if (passAllocationPtr) {
		kdmLog(L"[+] Pass Allocation Ptr as first param enabled" << std::endl);
	}

	if (copyHeader) {
		kdmLog(L"[+] Copying driver header enabled" << std::endl);
	}

#ifdef PDB_OFFSETS
	bool UpdateOffset = !(paramExists(argc, argv, L"dontUpdateOffsets") > 0);
	int FilePathParamIdx = paramExists(argc, argv, L"offsetsPath");
	std::wstring offsetFilePath = kdmUtils::GetCurrentAppFolder() + L"\\offsets.ini";

	if (UpdateOffset && FilePathParamIdx > 0) {
		kdmLog("[-] Can't set --offsetsPath without set --dontUpdateOffsets" << std::endl);
		help();
		return -1;
	}

	if (FilePathParamIdx > 0) {
		if (FilePathParamIdx + 1 >= argc) {
			help();
			return -1;
		}
		offsetFilePath = argv[FilePathParamIdx + 1];
		kdmLog("[+] Setting Offsets File Path To: " << offsetFilePath << std::endl);
	}
#endif

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0) {
		help();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		kdmLog(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}

#ifdef PDB_OFFSETS
	if (indPagesMode && !KDSymbolsHandler::GetInstance()->ReloadFile(offsetFilePath, UpdateOffset ? kdmUtils::GetCurrentAppFolder() + L"\\" + SYM_FROM_PDB_EXE : L"")) {
		kdmLog(L"[-] Error: Failed To Get Symbols Info." << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}
#endif

	std::vector<uint8_t> raw_image;
	if (!kdmUtils::ReadFileToMemory(driver_path, &raw_image)) {
		kdmLog(L"[-] Failed to read image to memory" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}
	PIMAGE_NT_HEADERS64 image_headers = nullptr;
	if (!portable_executable::ValidateFileImage(raw_image.data(), raw_image.size(), &image_headers)) {
		kdmLog(L"[-] Invalid or truncated driver image" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}
	NTSTATUS const helper_status = intel_driver::Load();
	if (!NT_SUCCESS(helper_status)) {
		kdmLog(L"[-] Helper load failed with NTSTATUS 0x" << std::hex << helper_status << std::dec << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}

	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocatePool;

	if (indPagesMode) {
		mode = kdmapper::AllocationMode::AllocateIndependentPages;
	}

	NTSTATUS exitCode = 0;
	kdmapper::map_result map_outcome{};
	if (!kdmapper::MapDriver(raw_image.data(), raw_image.size(), 0, 0, free, !copyHeader, mode, passAllocationPtr, callbackExample, &exitCode, &map_outcome)) {
		kdmLog(L"[-] Failed to map " << driver_path << std::endl);
		if (map_outcome.image_retained || !map_outcome.trampoline_intact) {
			kdmLog(L"[!] Retaining helper and possible kernel image at 0x" << std::hex << map_outcome.image_base << std::dec << std::endl);
			kdmLog(L"[!] Kernel call trampoline intact: " << map_outcome.trampoline_intact << std::endl);
		}
		else if (!NT_SUCCESS(intel_driver::Unload())) {
			kdmLog(L"[-] Failed to unload helper after mapping failure" << std::endl);
		}
		PauseIfParentIsExplorer();
		return -1;
	}

	if (!NT_SUCCESS(exitCode)) {
		kdmLog(L"[-] DriverEntry returned failure status 0x" << std::hex << exitCode << std::dec << std::endl);
		if (map_outcome.image_retained) {
			kdmLog(L"[!] Retaining helper and mapped image at 0x" << std::hex << map_outcome.image_base << std::dec << std::endl);
			PauseIfParentIsExplorer();
			return -1;
		}
	}

	if (!NT_SUCCESS(intel_driver::Unload())) {
		kdmLog(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}
	if (!NT_SUCCESS(exitCode))
		return -1;
	if (free && map_outcome.image_release_call_completed)
		kdmLog(L"[+] Kernel image release call completed; deallocation was not independently verified" << std::endl);
	kdmLog(L"[+] success" << std::endl);

}

#endif
