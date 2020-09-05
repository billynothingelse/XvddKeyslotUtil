#include <devioctl.h>
#include <iomanip>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdio.h>
#include <string>
#include <vector>

#include "cmdline.h"
#include "Common.h"
#include "KeBridge.h"
#include "ScpTypes.h"
#include "version.h"

static constexpr const char* s_UtilName = "XvddKeyslotUtil";
static constexpr const char* s_XvddDriverName = "xvdd.sys";

PVOID g_XvddBaseAddress = NULL;
PVOID g_XvddKeyslotAddress = NULL;
PVOID g_XvddGuidSlotAddress = NULL;

std::wstring g_DriverPath;
std::filesystem::path g_OutputPath;

std::vector<SCP_KEY_SLOT*> g_KeySlots;
std::vector<SCP_LICENSE> g_Licenses;

int main(int argc, char* argv[])
{
    cmdline::parser cmd;

    cmd.add<std::filesystem::path>(
        "output",
        'o',
        "output path for *.cik files",
        false,
        std::filesystem::current_path()
    );

    cmd.add<std::filesystem::path>(
        "kb",
        'd',
        "kernel-bridge driver path (to kernel-bridge.sys)",
        false,
        std::filesystem::current_path().append("kernel-bridge.sys")
    );

    std::cout << s_UtilName << " " << XVDD_KEYSLOT_UTIL_VERSION << std::endl;
    cmd.parse_check(argc, argv);

    std::cout << "[+] Checking if running with elevated privileges..." << std::endl;
    if (!IsProcessElevated()) {
        std::cout << "[-] No elevated privileges found, please run as Administrator!" << std::endl;
        return -1;
    }

    g_OutputPath = cmd.get<std::filesystem::path>("output");

    std::filesystem::path tmpPath = cmd.get<std::filesystem::path>("kb");
    std::string tmpPathString = tmpPath.string();
    g_DriverPath = std::wstring(tmpPathString.begin(), tmpPathString.end());

    std::cout << "[+] CIK output path: " << g_OutputPath << std::endl;
    std::wcout << "[+] Kernel Bridge driver path: " << g_DriverPath << std::endl;

    // Remove previous driver
    std::cout << "[+] Ensuring previous driver instance is removed..." << std::endl;
    KbDeleteDriver(s_KbDriverName);

    std::cout << "[+] Installing Kernel-Bridge driver..." << std::endl;
    if (!KbInstallDriver(g_DriverPath.c_str(), s_KbDriverName)) {
        std::cout << "[-] Failed to install Kernel-Bridge driver!" << std::endl;
        printf("Last error: %d\n", GetLastError());
        return -1;
    }

    std::cout << "[+] Opening Kernel-Bridge handle..." << std::endl;
    HANDLE hDriver = KbOpenHandle();

    if (hDriver == INVALID_HANDLE_VALUE) {
        std::cout << "[-] Unable to open Kernel-Bridge handle! "
                  << "Make sure the driver is enabled and running."
                  << std::endl;
        return -1;
    }

    std::cout << "[+] Getting " << s_XvddDriverName << "base address..." << std::endl;
    if (!GetKernelModuleBase(s_XvddDriverName, &g_XvddBaseAddress)) {
        std::cout << "[-] Unable to get XVDD.sys image base! "
                  << "Is GamingServices (ProductId: 9mwpm2cqnlhn) installed?"
                  << std::endl;
        return -1;
    }

    g_XvddKeyslotAddress = static_cast<char *>(g_XvddBaseAddress) + 0x72530;
    g_XvddGuidSlotAddress = static_cast<char *>(g_XvddBaseAddress) + 0x71144;

    // Gather current stored licenses
    SCP_GUID_SLOT *GuidSlots = {0};

    int GuidSlotCount = 0;

    std::cout << "[+] Fetching GUID slot table..." << std::endl;
    constexpr int GuidBufferSize = sizeof(SCP_GUID_SLOT);
    BYTE *GuidBuffer = new BYTE[GuidBufferSize];
    if (!ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(GuidBuffer), g_XvddGuidSlotAddress, GuidBufferSize)) {
        std::cout << "[-] Failed to fetch GUID slot table!" << std::endl;
        return -1;
    }

    GuidSlots = reinterpret_cast<SCP_GUID_SLOT*>(GuidBuffer);
    // Determine current loaded license count
    for (auto guid : GuidSlots->Data) {
        if (guid.EncryptionKeyGUID == GUID_NULL) {
            break;
        }
        GuidSlotCount++;
    }
    std::cout << "[+] Found " << GuidSlotCount << " GUID slots!" << std::endl;

    std::cout << "[+] Fetching keyslot table..." << std::endl;
    // Allocate memory for storing keyslots by slot count
    const int Size = sizeof(SCP_KEY_SLOT) * GuidSlotCount;
    BYTE *KeySlotBuffer = new BYTE[Size];
    if (!ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(KeySlotBuffer), g_XvddKeyslotAddress, Size)) {
        std::cout << "[-] Failed to fetch keyslot table!" << std::endl;
        return -1;
    }

    std::cout << "[*] Keyslots:" << std::endl;
    // Iterate through each slot and fetch keys
    for (int i = 0; i < GuidSlotCount; i++) {
        printf("\nEncryption GUID Slot: %d\n", i);
        SCP_KEY_SLOT *KeySlot = reinterpret_cast<SCP_KEY_SLOT *>(KeySlotBuffer + (0x3F0 * i));
        g_KeySlots.push_back(KeySlot);

        SCP_KEY_DATA DataKey = KeySlot->KeyDataBegin[0];
        print_bytes("Data Key", DataKey.Data, sizeof(SCP_KEY_DATA));
        SCP_KEY_DATA TweakKey = KeySlot->KeyDataEnd[0];
        print_bytes("Tweak Key", TweakKey.Data, sizeof(SCP_KEY_DATA));

        SCP_LICENSE exportLicense = {0};
        exportLicense.KeyGUID = GuidSlots[i].Data->EncryptionKeyGUID;
        exportLicense.DataKey = DataKey;
        exportLicense.TweakKey = TweakKey;

        std::filesystem::path tmp_path = g_OutputPath;
        std::string filename = tmp_path.append(GuidToString(exportLicense.KeyGUID) + ".cik").string();
        FILE *f = NULL;
        fopen_s(&f, filename.c_str(), "w");
        fwrite(&exportLicense, sizeof(SCP_LICENSE), 1, f);
        fclose(f);

        std::cout << "[+] Written to file: " << filename << std::endl;
    }

    // Cleanup
    delete[] GuidBuffer;
    delete[] KeySlotBuffer;

    return 0;
}
