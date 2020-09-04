#include <devioctl.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "Common.h"
#include "KeBridge.h"
#include "ScpTypes.h"

static constexpr const char* s_XvddDriverName = "xvdd.sys";

PVOID g_XvddBaseAddress = NULL;
PVOID g_XvddKeyslotAddress = NULL;
PVOID g_XvddGuidSlotAddress = NULL;

std::vector<SCP_KEY_SLOT*> g_KeySlots;
std::vector<SCP_LICENSE> g_Licenses;

int main()
{
    HANDLE hDriver = KbOpenHandle();
    if (hDriver == INVALID_HANDLE_VALUE) {
        std::cout << "Unable to open Kernel-Bridge handle!"
            << "Make sure the driver is enabled and running."
            << std::endl;
        return -1;
    }

    if (!GetKernelModuleBase(s_XvddDriverName, &g_XvddBaseAddress)) {
        std::cout << "Unable to get XVDD.sys image base!" << std::endl;
        return 1;
    }

    if (g_XvddBaseAddress) {
        g_XvddKeyslotAddress = static_cast<char*>(g_XvddBaseAddress) + 0x72530;
        g_XvddGuidSlotAddress = static_cast<char*>(g_XvddBaseAddress) + 0x71144;
        if (g_XvddKeyslotAddress && g_XvddGuidSlotAddress) {
            // Gather current stored licenses
            SCP_GUID_SLOT* GuidSlots = { 0 };

            int GuidSlotCount = 0;
            int AvailableKeyslots = 0;

            constexpr int GuidBufferSize = sizeof(SCP_GUID_SLOT);
            BYTE GuidBuffer[GuidBufferSize] = { 0 };
            if (ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(GuidBuffer), g_XvddGuidSlotAddress, GuidBufferSize)) {
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
                    bool bResult = ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(KeySlotBuffer), g_XvddKeyslotAddress, Size);
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

    return 0;
}
