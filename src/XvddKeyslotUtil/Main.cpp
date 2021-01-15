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

PVOID XvddBaseAddress = NULL;
PVOID XvddKeyslotAddress = NULL;
PVOID XvddGuidSlotAddress = NULL;

std::wstring g_DriverPath;
std::filesystem::path g_OutputPath;

int GuidSlotCount = 0;

SCP_GUID_SLOT GuidSlots[MAX_GUID_SLOTS] = {0};
SCP_KEY_SLOT KeySlots[MAX_GUID_SLOTS] = {0};

int main(int argc, char* argv[])
{
    cmdline::parser cmd;

    cmd.add(
        "help",
        '\0',
        "print usage"
        );

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

    std::cout << s_UtilName << " "
              << XVDD_KEYSLOT_UTIL_VERSION << " "
              << "(" << COMPILE_TIME << ")"
              << std::endl;

    cmd.parse_check(argc, argv);

    if (cmd.exist("help")) {
        cmd.usage();
    }

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
    if (!GetKernelModuleBase(s_XvddDriverName, &XvddBaseAddress)) {
        std::cout << "[-] Unable to get XVDD.sys image base! "
            << "Is GamingServices (ProductId: 9mwpm2cqnlhn) installed?"
            << std::endl;
        return -1;
    }

    // 10.0.19041.3952
    //XvddKeyslotAddress = static_cast<char*>(XvddBaseAddress) + 0x72530;
    //XvddGuidSlotAddress = static_cast<char*>(XvddBaseAddress) + 0x71144;

    // 10.0.19041.5411
    XvddKeyslotAddress = static_cast<char*>(XvddBaseAddress) + 0x72580;
    XvddGuidSlotAddress = static_cast<char*>(XvddBaseAddress) + 0x71194;

    std::cout << "[+] Fetching GUID slot table..." << std::endl;

    // Fetch GUID slot table
    if (!ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(GuidSlots), XvddGuidSlotAddress, sizeof(GuidSlots))) {
        std::cout << "[-] Failed to fetch GUID slot table!" << std::endl;
        return -1;
    }

    // Determine current loaded license count
    for (auto guid : GuidSlots) {
        if (guid.EncryptionKeyGUID == GUID_NULL) {
            break;
        }
        GuidSlotCount++;
    }
    std::cout << "[+] Found " << GuidSlotCount << " GUID slots!" << std::endl;

    std::cout << "[+] Fetching keyslot table..." << std::endl;

    // Fetch keyslot table
    if (!ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(KeySlots), XvddKeyslotAddress, sizeof(KeySlots))) {
        std::cout << "[-] Failed to fetch keyslot table!" << std::endl;
        return -1;
    }

    std::cout << "[*] Keyslots:" << std::endl;
    // Iterate through each slot and fetch keys
    for (int i = 0; i < GuidSlotCount; i++) {
        printf("\nEncryption GUID Slot: %d\n", i);

        SCP_KEY_DATA DataKey = KeySlots[i].KeyDataBegin[0];
        print_bytes("Data Key", DataKey.Data, sizeof(SCP_KEY_DATA));
        SCP_KEY_DATA TweakKey = KeySlots[i].KeyDataEnd[0];
        print_bytes("Tweak Key", TweakKey.Data, sizeof(SCP_KEY_DATA));

        SCP_LICENSE exportLicense = { 0 };
        exportLicense.KeyGUID = GuidSlots[i].EncryptionKeyGUID;
        exportLicense.DataKey = DataKey;
        exportLicense.TweakKey = TweakKey;

        std::filesystem::path tmp_path = g_OutputPath;
        std::string filename = tmp_path.append(GuidToString(exportLicense.KeyGUID) + ".cik").string();
        FILE* f = NULL;
        fopen_s(&f, filename.c_str(), "wb");
        fwrite(&exportLicense, sizeof(SCP_LICENSE), 1, f);
        fflush(f);
        fclose(f);

        std::cout << "[+] Written to file: " << filename << std::endl;
    }

    // Cleanup
    delete[] GuidSlots;
    delete[] KeySlots;

    return 0;
}
