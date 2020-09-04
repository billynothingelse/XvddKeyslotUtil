#pragma once

#include <Windows.h>

#define CTL_BASE (0x800)

struct KB_COPY_MOVE_MEMORY_IN {
    PVOID Src;
    PVOID Dest;
    ULONG Size;
    BOOLEAN Intersects;
};

HANDLE KbOpenHandle(LPCWSTR DeviceName = L"\\\\.\\Kernel-Bridge");

BOOL ReadKernelMemory(HANDLE hDriver, OUT PVOID Dest, IN PVOID Src, IN ULONG Size);
