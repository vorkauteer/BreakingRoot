#include "recon_modules.h"
#include <cstdio>
#include <windows.h>
#include <winternl.h>
#include <lm.h>
#include <tlhelp32.h>
#include <cstdlib>
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

extern "C" NTSYSAPI NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW);

void RunHostInfo() {
    CHAR computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    printf("Computer Name: %s\n", computerName);
    
    CHAR userName[256];
    DWORD userSize = sizeof(userName);
    GetUserNameA(userName, &userSize);
    printf("Current User: %s\n", userName);
}

void RunOsInfo() {
    OSVERSIONINFOEXW osvi = { sizeof(osvi) };
    RtlGetVersion((PRTL_OSVERSIONINFOW)&osvi);
    printf("OS: %S %d.%d build %d\n", 
           osvi.szCSDVersion, osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    printf("Processor Arch: %d, %d cores\n", si.wProcessorArchitecture, si.dwNumberOfProcessors);
}

void RunUserEnum() {
    LPUSER_INFO_0 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS status = NetUserEnum(NULL, 0, 0, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
    if (status == NERR_Success && pBuf) {
        printf("Local users:\n");
        for (DWORD i = 0; i < entriesRead; i++) {
            printf("  %S\n", pBuf[i].usri0_name);
        }
        NetApiBufferFree(pBuf);
    } else {
        printf("Failed to enumerate users (error %d)\n", status);
    }
}

void RunGroupEnum() {
    LPLOCALGROUP_INFO_0 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS status = NetLocalGroupEnum(NULL, 0, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
    if (status == NERR_Success && pBuf) {
        printf("Local groups:\n");
        for (DWORD i = 0; i < entriesRead; i++) {
            printf("  %S\n", pBuf[i].lgrpi0_name);
        }
        NetApiBufferFree(pBuf);
    } else {
        printf("Failed to enumerate groups\n");
    }
}

void RunShareEnum() {
    PSHARE_INFO_502 pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0, resumeHandle = 0;
    NET_API_STATUS status = NetShareEnum(NULL, 502, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resumeHandle);
    if (status == NERR_Success && pBuf) {
        printf("Network shares:\n");
        for (DWORD i = 0; i < entriesRead; i++) {
            printf("  %S -> %S\n", pBuf[i].shi502_netname, pBuf[i].shi502_path);
        }
        NetApiBufferFree(pBuf);
    } else {
        printf("No shares or access denied.\n");
    }
}

void RunServiceEnum() {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCM) return;
    DWORD needed = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &needed, &servicesReturned, &resumeHandle);
    DWORD bytes = needed;
    LPENUM_SERVICE_STATUSA pServices = (LPENUM_SERVICE_STATUSA)malloc(bytes);
    if (EnumServicesStatusA(hSCM, SERVICE_WIN32, SERVICE_STATE_ALL, pServices, bytes, &needed, &servicesReturned, &resumeHandle)) {
        printf("Windows services (running):\n");
        for (DWORD i = 0; i < servicesReturned; i++) {
            if (pServices[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING)
                printf("  %s - %s\n", pServices[i].lpServiceName, pServices[i].lpDisplayName);
        }
    }
    free(pServices);
    CloseServiceHandle(hSCM);
}

void RunSessionEnum() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        printf("Active sessions (processes with interactive users):\n");
        do {
            if (pe.th32ProcessID != 0 && pe.th32ProcessID != 4) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProc) {
                    HANDLE hToken = NULL;
                    if (OpenProcessToken(hProc, TOKEN_QUERY, &hToken)) {
                        DWORD sessionId = 0;
                        DWORD size = sizeof(sessionId);
                        if (GetTokenInformation(hToken, TokenSessionId, &sessionId, size, &size)) {
                            if (sessionId != 0) {
                                printf("  PID %d (%S) Session %d\n", pe.th32ProcessID, pe.szExeFile, sessionId);
                            }
                        }
                        CloseHandle(hToken);
                    }
                    CloseHandle(hProc);
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}