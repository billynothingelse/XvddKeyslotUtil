#pragma once

#include <array>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")

#define SystemModuleInformation ((SYSTEM_INFORMATION_CLASS)11)

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

BOOL GetKernelModuleBase(IN const char* ModuleName, OUT LPVOID* lpAddr)
{
    NTSTATUS Status = STATUS_INVALID_HANDLE;

    PRTL_PROCESS_MODULES ModuleInfo =
        (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (ModuleInfo) {
        Status = NtQuerySystemInformation(SystemModuleInformation, ModuleInfo, 1024 * 1024, NULL);
        if (FAILED(Status)) {
            VirtualFree(ModuleInfo, NULL, MEM_RELEASE);
            return false;
        }

        for (ULONG i = 0; i < ModuleInfo->NumberOfModules; i++) {
            CONST USHORT OffsetToFileName = ModuleInfo->Modules[i].OffsetToFileName;
            if (!strncmp((const char*)&ModuleInfo->Modules[i].FullPathName[OffsetToFileName], ModuleName, 4)) {
                *lpAddr = ModuleInfo->Modules[i].ImageBase;
                break;
            }
        }
        VirtualFree(ModuleInfo, NULL, MEM_RELEASE);
        return true;
    }

    return false;
}

// https://stackoverflow.com/a/27173017
void print_bytes(const char* title, const unsigned char* data, size_t dataLen, bool format = true) {
    std::cout << title << std::endl;
    std::cout << std::setfill('0');
    for (size_t i = 0; i < dataLen; ++i) {
        std::cout << std::hex << std::setw(2) << (int)data[i];
        if (format) {
            std::cout << (((i + 1) % 16 == 0) ? "\n" : " ");
        }
    }
    std::cout << std::endl;
}

std::string GuidToString(GUID guid) 
{
    std::array<char, 40> output;
    snprintf(output.data(), output.size(), "%08X-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X", guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
    return std::string(output.data());
}
