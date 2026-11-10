#include "service.hpp"
#include <Windows.h>
#include <string>
#include <iostream>

#include "utils.hpp"
#include "nt.hpp"

NTSTATUS service::RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName) {
	const static DWORD ServiceTypeKernel = 1;
	const std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	const std::wstring nPath = L"\\??\\" + driver_path;

	HKEY dservice;
	DWORD disposition = 0;
	LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), 0,
		nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &dservice, &disposition);
	if (status != ERROR_SUCCESS) {
		kdmLog("[-] Can't create service key" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}
	if (disposition != REG_CREATED_NEW_KEY) {
		RegCloseKey(dservice);
		kdmLog("[-] Refusing to reuse an existing driver service key" << std::endl);
		return STATUS_ALREADY_REGISTERED;
	}

	status = RegSetKeyValueW(dservice, NULL, L"ImagePath", REG_EXPAND_SZ, nPath.c_str(), (DWORD)((nPath.size() + 1) * sizeof(wchar_t)));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		kdmLog("[-] Can't create 'ImagePath' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}
	
	status = RegSetKeyValueW(dservice, NULL, L"Type", REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS) {
		RegCloseKey(dservice);
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		kdmLog("[-] Can't create 'Type' registry value" << std::endl);
		return STATUS_REGISTRY_IO_FAILED;
	}
	
	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (ntdll == NULL) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		return STATUS_UNSUCCESSFUL;
	}

	//auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	//auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, "NtLoadDriver");

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS ntStatus = nt::RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(ntStatus)) {
		RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		kdmLog("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator." << std::endl);
		return ntStatus;
	}

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	ntStatus = nt::NtLoadDriver(&serviceStr);

	kdmLog("[+] NtLoadDriver Status 0x" << std::hex << ntStatus << std::endl);

	if (ntStatus == STATUS_IMAGE_CERT_REVOKED) {
		kdmLog("[-] Windows code integrity rejected the helper driver on this configuration" << std::endl);
	}
	else if (ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_INSUFFICIENT_RESOURCES) {
		kdmLog("[-] Access Denied or Insufficient Resources (0x" << std::hex << ntStatus << "), Probably some anticheat or antivirus running blocking the load of vulnerable driver" << std::endl);
	}
	
	if (!NT_SUCCESS(ntStatus)) {
		//Remove the service
		status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
		if (status != ERROR_SUCCESS) {
			kdmLog("[-] Can't delete service registry key after NtLoadDriver failure" << std::endl);
		}
	}

	return ntStatus;
}

NTSTATUS service::StopAndRemove(const std::wstring& serviceName,
	bool driver_already_unloaded, bool* driver_unloaded) {
	if (driver_unloaded) *driver_unloaded = driver_already_unloaded;
	if (!driver_already_unloaded && GetModuleHandleA("ntdll.dll") == NULL)
		return STATUS_UNSUCCESSFUL;

	std::wstring wdriver_reg_path = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\" + serviceName;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_reg_path.c_str());

	HKEY driver_service;
	std::wstring servicesPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
	LSTATUS status = RegOpenKeyW(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_FILE_NOT_FOUND) {
			return driver_already_unloaded ? STATUS_SUCCESS : STATUS_NOT_FOUND;
		}
		return STATUS_REGISTRY_IO_FAILED;
	}
	RegCloseKey(driver_service);

	if (!driver_already_unloaded) {
		NTSTATUS const st = nt::NtUnloadDriver(&serviceStr);
		kdmLog("[+] NtUnloadDriver Status 0x" << std::hex << st << std::endl);
		if (!NT_SUCCESS(st)) {
			kdmLog("[-] Driver Unload Failed!!" << std::endl);
			return st; // Keep the service key so this helper can be retried.
		}
		if (driver_unloaded) *driver_unloaded = true;
	}

	status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS) {
		return STATUS_REGISTRY_IO_FAILED;
	}
	return STATUS_SUCCESS;
}
