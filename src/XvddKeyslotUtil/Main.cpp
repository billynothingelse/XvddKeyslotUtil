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

#define UTIL_NAME "XvddKeyslotUtil"
#define XVDD_DRIVER_NAME "xvdd.sys"
// Size to dump from xvdd.sys kernel memory to find keytable
#define XVDD_DRIVER_DUMP_SIZE 0x80000

static std::string s_DevTestCikGuid = "33EC8436-5A0E-4F0D-B1CE-3F29C3955039";
static const BYTE s_DevTestCikGuidBytes[16] = {
    0x36, 0x84, 0xec, 0x33,
    0x0e, 0x5a,
    0x0d, 0x4f,
    0xb1, 0xce,
    0x3f, 0x29, 0xc3, 0x95, 0x50, 0x39     
};

static std::map<intptr_t, std::string> s_KeytableAddressMap {
    {0x71144, "10.0.19041.3952"},
    {0x72194, "10.0.19041.5035"},
    {0x71194, "10.0.19041.5411"}
};

int exit_fail() {
    KbDeleteDriver(s_KbDriverName);
    return -1;
}

int extract_keys(std::filesystem::path outputPath, std::filesystem::path kbDriverPath)
{
    PVOID XvddBaseAddress = NULL;
    std::vector<intptr_t> possibleKeytableAddresses{};

    BYTE XvddMemory[XVDD_DRIVER_DUMP_SIZE] = {0};

    int GuidSlotCount = 0;
    SCP_KEY_TABLE KeyTable = {0};

    std::string tmpdriverPath = kbDriverPath.string();
    std::wstring wstrDriverPath = std::wstring(tmpdriverPath.begin(), tmpdriverPath.end());

    std::cout << "[+] CIK output path: " << outputPath << std::endl;
    std::wcout << "[+] Kernel Bridge driver path: " << kbDriverPath << std::endl;

    // Remove previous driver
    std::cout << "[+] Ensuring previous driver instance is removed..." << std::endl;
    KbDeleteDriver(s_KbDriverName);

    std::cout << "[+] Installing Kernel-Bridge driver..." << std::endl;
    if (!KbInstallDriver(kbDriverPath.c_str(), s_KbDriverName)) {
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
        return exit_fail();
    }

    std::cout << "[+] Getting " << XVDD_DRIVER_NAME << " base address..." << std::endl;
    if (!GetKernelModuleBase(XVDD_DRIVER_NAME, &XvddBaseAddress)) {
        std::cout << "[-] Unable to get XVDD.sys image base! "
            << "Is GamingServices (ProductId: 9mwpm2cqnlhn) installed?"
            << std::endl;
        return exit_fail();
    }
    std::cout << "[*] XVDD.sys base address: 0x" << std::hex << XvddBaseAddress << std::endl;

    std::cout << "[+] Dumping xvdd.sys memory from kernel-space..." << std::endl;
    if (!ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(&XvddMemory), XvddBaseAddress, sizeof(XvddMemory))) {
        std::cout << "[-] Failed to read xvdd.sys memory!" << std::endl;
        return exit_fail();
    }

    std::cout << "[+] Searching for keytable candidates in memory dump..." << std::endl;
    for (int i=0; i < (XVDD_DRIVER_DUMP_SIZE - 16); i += 4) {
        if (!memcmp(&XvddMemory[i], s_DevTestCikGuidBytes, 16)) {
            std::cout << "[*] Found possible Keytable candidate @ 0x" << std::hex << i << std::endl;
            possibleKeytableAddresses.push_back((uintptr_t)i);
        }
    }

    if (possibleKeytableAddresses.size() == 0) {
        std::cout << "[-] Did not find any keytable candidate!" << std::endl;
        return exit_fail();
    }

    intptr_t finalAddress = NULL;
    for (auto relativeAddress : possibleKeytableAddresses) {

        PVOID tmpAddr = (PVOID)((PCHAR)XvddBaseAddress + relativeAddress);
        std::cout << "[+] Fetching Keytable candidate from 0x" << std::hex << tmpAddr << " (rel. 0x" << std::hex << relativeAddress << ") ..." << std::endl;
        if (!ReadKernelMemory(hDriver, reinterpret_cast<PVOID>(&KeyTable), tmpAddr, sizeof(KeyTable))) {
            std::cout << "[-] Failed to fetch Key table!" << std::endl;
            return exit_fail();
        }

        if (GuidToString(KeyTable.Guids[0].EncryptionKeyGUID) != s_DevTestCikGuid || 
            KeyTable.KeySlots[0].KeyDataBegin[0].Data[0] != 0x9A ||
            KeyTable.KeySlots[0].KeyDataBegin[0].Data[1] != 0xB6 ||
            KeyTable.KeySlots[0].KeyDataBegin[0].Data[2] != 0xDC
        )  {
            // std::cout << "[-] First GUID in Key table does not match expected DevTest (RED)" << std::endl;
            continue;
        }

        finalAddress = relativeAddress;
        break;
    }

    if (finalAddress == NULL) {
        std::cout << "[-] No valid keytable found!" << std::endl;
        return exit_fail();
    }

    std::cout << "[*] Valid keytable found! Address: 0x" << std::hex << finalAddress << std::endl;

    auto knownDriverVersion = s_KeytableAddressMap.find(finalAddress);
    if (knownDriverVersion != s_KeytableAddressMap.end()) {
        std::cout << "[*] GamingServices version: " << knownDriverVersion->second << std::endl;
    } else {
        std::cout << "[*] UNKNOWN GamingServices version!" << std::endl;
    }

    // Determine current loaded license count
    for (auto guid : KeyTable.Guids) {
        if (guid.EncryptionKeyGUID == GUID_NULL) {
            break;
        }
        GuidSlotCount++;
    }
    std::cout << "[+] Found " << std::dec << GuidSlotCount << " Key slots!" << std::endl;

    std::cout << "[*] Keyslots:" << std::endl;
    // Iterate through each slot and fetch keys
    for (int i = 0; i < GuidSlotCount; i++) {
        std::cout << "Encryption GUID Slot: " << std::dec << i << std::endl;
        std::cout << "GUID: " << GuidToString(KeyTable.Guids[i].EncryptionKeyGUID) << std::endl;
        SCP_KEY_DATA DataKey = KeyTable.KeySlots[i].KeyDataBegin[0];
        print_bytes("Data Key", DataKey.Data, sizeof(SCP_KEY_DATA));
        SCP_KEY_DATA TweakKey = KeyTable.KeySlots[i].KeyDataEnd[0];
        print_bytes("Tweak Key", TweakKey.Data, sizeof(SCP_KEY_DATA));

        SCP_LICENSE exportLicense = { 0 };
        exportLicense.KeyGUID = KeyTable.Guids[i].EncryptionKeyGUID;
        exportLicense.DataKey = DataKey;
        exportLicense.TweakKey = TweakKey;

        std::filesystem::path tmp_path = outputPath;
        std::string filename = tmp_path.append(GuidToString(exportLicense.KeyGUID) + ".cik").string();
        FILE* f = NULL;
        fopen_s(&f, filename.c_str(), "wb");
        fwrite(&exportLicense, sizeof(SCP_LICENSE), 1, f);
        fflush(f);
        fclose(f);

        std::cout << "[+] Written to file: " << filename << std::endl;
    }

    // Cleanup
    KbDeleteDriver(s_KbDriverName);

    return 0;
}

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

    std::cout << UTIL_NAME << " "
              << XVDD_KEYSLOT_UTIL_VERSION << " "
              << "(" << COMPILE_TIME << ")"
              << std::endl;

    cmd.parse_check(argc, argv);

    if (cmd.exist("help")) {
        cmd.usage();
        return 0;
    }

    std::cout << "[+] Checking if running with elevated privileges..." << std::endl;
    if (!IsProcessElevated()) {
        std::cout << "[-] No elevated privileges found, please run as Administrator!" << std::endl;
        return -1;
    }

    return extract_keys(
        cmd.get<std::filesystem::path>("output"),
        cmd.get<std::filesystem::path>("kb")
    );
}
