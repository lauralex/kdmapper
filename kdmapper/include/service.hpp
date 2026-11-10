#pragma once
#include <string>
#include "nt.hpp"

namespace service
{
	NTSTATUS RegisterAndStart(const std::wstring& driver_path, const std::wstring& serviceName);
	NTSTATUS StopAndRemove(const std::wstring& serviceName,
		bool driver_already_unloaded = false, bool* driver_unloaded = nullptr);
};
