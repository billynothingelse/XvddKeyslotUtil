#pragma once

#include <Windows.h>

#define CTL_BASE (0x800)

static constexpr LPCWSTR s_KbDriverName = L"KernelBridge";
static constexpr LPCWSTR s_KbDeviceName = L"\\\\.\\Kernel-Bridge";

struct KB_COPY_MOVE_MEMORY_IN {
    PVOID Src;
    PVOID Dest;
    ULONG Size;
    BOOLEAN Intersects;
};

BOOL KbInstallDriver(LPCWSTR FilePath, LPCWSTR DriverName, DWORD DriverType = SERVICE_KERNEL_DRIVER);

BOOL KbDeleteDriver(LPCWSTR DriverName);

HANDLE KbOpenHandle(LPCWSTR DeviceName = L"\\\\.\\Kernel-Bridge");

BOOL ReadKernelMemory(HANDLE hDriver, OUT PVOID Dest, IN PVOID Src, IN ULONG Size);
