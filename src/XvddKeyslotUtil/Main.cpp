#include <devioctl.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "KeBridge.h"

#pragma comment(lib,"ntdll.lib")

#define SystemModuleInformation ((SYSTEM_INFORMATION_CLASS)11)

static constexpr LPCWSTR s_lpDriverName = L"\\\\.\\Kernel-Bridge";
static constexpr const char* s_XvddDriverName = "xvdd.sys";

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

#pragma pack(push, 1)
struct SCP_KEY_DATA {
    BYTE Data[0x10];
};

struct SCP_KEY_SLOT {
    SCP_KEY_DATA SlotIdBegin;
    SCP_KEY_DATA KeyDataBegin[29];
    GUID Guid;
    SCP_KEY_DATA SlotIdEnd;
    SCP_KEY_DATA KeyDataEnd[29];
};

struct SCP_LICENSE {
    GUID KeyGUID;
    SCP_KEY_DATA FirstKey;
    SCP_KEY_DATA SecondKey;
};

struct SCP_GUID_SLOT_CONTENT
{
    GUID EncryptionKeyGUID;
    uint16_t FirstKeyId;
    uint16_t SecondKeyId;
};

struct SCP_GUID_SLOT {
    SCP_GUID_SLOT_CONTENT Data[64];
};
#pragma pack(pop)

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

std::vector<SCP_KEY_SLOT*> g_KeySlots;
std::vector<SCP_LICENSE> g_Licenses;

int main()
{
    HANDLE hDriver = KbOpenHandle(s_lpDriverName);

    if (hDriver != INVALID_HANDLE_VALUE)
    {
        PVOID XvddBaseAddress = NULL;
        
        LookupXvddBaseAddress(&XvddBaseAddress);

        if (XvddBaseAddress) {  
            PVOID XvddKeyslotAddress = static_cast<char*>(XvddBaseAddress) + 0x72530;
            PVOID XvddGuidSlotAddress = static_cast<char*>(XvddBaseAddress) + 0x71144;
            if (XvddKeyslotAddress && XvddGuidSlotAddress) {
                // Gather current stored licenses
                SCP_GUID_SLOT* GuidSlots = { 0 };

                int GuidSlotCount = 0;
                int AvailableKeyslots = 0;

                constexpr int GuidBufferSize = sizeof(SCP_GUID_SLOT);
                BYTE GuidBuffer[GuidBufferSize] = { 0 };
                if (ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(GuidBuffer), XvddGuidSlotAddress, GuidBufferSize)) {
                    GuidSlots = reinterpret_cast<SCP_GUID_SLOT*>(GuidBuffer);
                    if (GuidSlots) {
                        // Determine current loaded license count
                        for (auto guid : GuidSlots->Data) {
                            if (guid.EncryptionKeyGUID != GUID_NULL)
                                GuidSlotCount++;
                        }

                        AvailableKeyslots = GuidSlotCount * 2;

                        // Allocate memory for storing keyslots
                        const int Size = sizeof(SCP_KEY_SLOT) * AvailableKeyslots;
                        BYTE* KeySlotBuffer = new BYTE[Size];
                        bool bResult = ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(KeySlotBuffer), XvddKeyslotAddress, Size);
                        if (bResult) {
                            // Iterate through each slot and fetch keys
                            for (int i = 0; i < GuidSlotCount; i++) {
                                printf("\nEncryption GUID Slot: %d\n", i);
                                SCP_KEY_SLOT* KeySlot = reinterpret_cast<SCP_KEY_SLOT*>(KeySlotBuffer + (0x3F0 * i));
                                g_KeySlots.push_back(KeySlot);
                                
                                SCP_KEY_DATA DataKey = KeySlot->KeyDataBegin[0];
                                print_bytes("Data Key", DataKey.Data, sizeof(SCP_KEY_DATA));
                                SCP_KEY_DATA TweakKey = KeySlot->KeyDataEnd[0];
                                print_bytes("Tweak Key", TweakKey.Data, sizeof(SCP_KEY_DATA));
                            }
                        }
                        // Cleanup
                        delete[] KeySlotBuffer;
                    }
                }
            }
        }
    }

    return 0;
}
