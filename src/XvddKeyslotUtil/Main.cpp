#include <iostream>
#include <devioctl.h>
#include <windows.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")

#define CTL_BASE (0x800)
#define SystemModuleInformation ((SYSTEM_INFORMATION_CLASS)11)

static constexpr LPCWSTR s_lpDriverName = L"\\\\.\\Kernel-Bridge";
static HANDLE s_hDriver = INVALID_HANDLE_VALUE;

static constexpr const char* s_XvddDriverName = "xvdd.sys";

struct KB_COPY_MOVE_MEMORY_IN {
    PVOID Src;
    PVOID Dest;
    ULONG Size;
    BOOLEAN Intersects;
};

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
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

HANDLE KbOpenHandle(LPCWSTR DeviceName)
{
    return CreateFileW(DeviceName, NULL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);
}

BOOL ReadKernelMemory(OUT PVOID Dest, IN PVOID Src, IN ULONG Size)
{
    if (!Dest || !Src || !Size)
        return FALSE;

    KB_COPY_MOVE_MEMORY_IN Data = { 0 };
    Data.Src = Src;
    Data.Dest = Dest;
    Data.Size = Size;
    Data.Intersects = FALSE;

    if (!s_hDriver)
        return FALSE;

    DWORD dwIoCtl = CTL_CODE(0x8000, CTL_BASE + 27, 0, FILE_ANY_ACCESS);
    if (!DeviceIoControl(s_hDriver, dwIoCtl, &Data, sizeof(Data), nullptr, NULL, NULL, NULL))
        return FALSE;

    return TRUE;
}

BOOL LookupXvddBaseAddress(OUT LPVOID *lpAddr)
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
            if (!strncmp((const char*)&ModuleInfo->Modules[i].FullPathName[OffsetToFileName], s_XvddDriverName, 4)) {
                *lpAddr = ModuleInfo->Modules[i].ImageBase;
                break;
            }
        }
        VirtualFree(ModuleInfo, NULL, MEM_RELEASE);
        return true;
    }

    return false;
}

struct SCP_KEY_DATA {
    BYTE Data[0x10];
};

#pragma pack(push, 1)
struct SCP_KEY_SLOT {
    BYTE SlotIdBegin[0x10];
    SCP_KEY_DATA KeyDataBegin[29];
    GUID Guid;
    BYTE SlotIdEnd[0x10];
    SCP_KEY_DATA KeyDataEnd[29];
};
#pragma pack(pop)

int main()
{
    s_hDriver = KbOpenHandle(s_lpDriverName);

    if (s_hDriver != INVALID_HANDLE_VALUE)
    {
        PVOID XvddBaseAddress = NULL;
        
        LookupXvddBaseAddress(&XvddBaseAddress);

        if (XvddBaseAddress) {  
            PVOID XvddKeyslotAddress = static_cast<char*>(XvddBaseAddress) + 0x72530;
            PVOID XvddGuidSlotAddress = static_cast<char*>(XvddBaseAddress) + 0x71144;
            if (XvddKeyslotAddress && XvddGuidSlotAddress)
            {
                SCP_KEY_SLOT* BaseSlot = { 0 };

                constexpr int Size = sizeof(SCP_KEY_SLOT);
                BYTE Buffer[Size] = { 0 };
                if (ReadKernelMemory(reinterpret_cast<PVOID>(Buffer), XvddKeyslotAddress, Size))
                {
                    BaseSlot = reinterpret_cast<SCP_KEY_SLOT*>(Buffer);
                    printf("Keyslot GUID = {%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
                        BaseSlot->Guid.Data1, BaseSlot->Guid.Data2, BaseSlot->Guid.Data3,
                        BaseSlot->Guid.Data4[0], BaseSlot->Guid.Data4[1], BaseSlot->Guid.Data4[2], BaseSlot->Guid.Data4[3],
                        BaseSlot->Guid.Data4[4], BaseSlot->Guid.Data4[5], BaseSlot->Guid.Data4[6], BaseSlot->Guid.Data4[7]);
                }
            }
        }
    }

    return 0;
}
