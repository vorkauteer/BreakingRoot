#include "command.h"
#include "app.h"
#include "defense.h"
#include "recon_modules.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <string>
#include <vector>
#include <algorithm>

#ifdef _WIN32
#include <conio.h>
#endif

static DefenseStatus defenseStatus{};

enum class CommandType {
    None = 0,
    Help,
    Exit,
    Status,
    Use,
    Back,
    List,
    Show,
    Run,
    CmdVersion,
    CmdClear,
    CmdBanner,
    PowerShellEncoded,
    ScheduledTaskCreate,
    RegistryAutoRunSet,
    ProxyCertutil,
    ReconAll,
    BypassAMSIETW,
    Lsass,
    CmdSam,
    CmdLsa,
    CmdDpapi,
    CmdNtlm,
    CmdKerberos,
    CmdSessionModule,
    CmdSessionWorkspace,
    CmdSessionReset,
    Unknown
};

static CommandType GetCommandType(const char* input);
static bool HandleDirectPathCommand(Target* target, CliState* cli, const char* input);

static void ClearSelectedModule(CliState* cli) {
    if (cli == nullptr) return;
    cli->currentRecon = ReconModule::None;
    cli->currentCreds = CredsModule::None;
    cli->currentSession = SessionModule::None;
    cli->currentConfig = ConfigModule::None;
}

static const char* GetArgumentAfterPrefix(const char* input, std::size_t prefixLength) {
    if (input == nullptr) return nullptr;
    const char* arg = input + prefixLength;
    return (*arg == '\0') ? nullptr : arg;
}

static std::string ToLowerAscii(const char* text) {
    std::string result = text ? text : "";
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return result;
}

static void SplitCommandAndArgs(const char* input, std::string& command, const char*& args) {
    command.clear();
    args = nullptr;

    if (input == nullptr) return;

    while (*input == ' ' || *input == '\t') ++input;

    const char* cursor = input;
    while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t') ++cursor;

    command.assign(input, static_cast<std::size_t>(cursor - input));
    command = ToLowerAscii(command.c_str());

    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    if (*cursor != '\0') args = cursor;
}

static bool ParseTwoArgs(const char* args, char* first, std::size_t firstSize, char* second, std::size_t secondSize) {
    if (args == nullptr || first == nullptr || second == nullptr || firstSize == 0 || secondSize == 0) return false;

    first[0] = '\0';
    second[0] = '\0';

    char format[64];
    std::snprintf(format, sizeof(format), "%%%zus %%%zus", firstSize - 1, secondSize - 1);
    return std::sscanf(args, format, first, second) == 2;
}

static void RunReconModule(ReconModule module) {
    switch (module) {
    case ReconModule::HostInfo:
        RunHostInfo();
        break;
    case ReconModule::OsInfo:
        RunOsInfo();
        break;
    case ReconModule::UserEnum:
        RunUserEnum();
        break;
    case ReconModule::GroupEnum:
        RunGroupEnum();
        break;
    case ReconModule::ShareEnum:
        RunShareEnum();
        break;
    case ReconModule::ServiceEnum:
        RunServiceEnum();
        break;
    case ReconModule::SessionEnum:
        RunSessionEnum();
        break;
    default:
        std::printf("[-] No recon module selected.\n");
        break;
    }
    std::printf("\n");
}

static void RunCredsModule(CredsModule module) {
    switch (module) {
    case CredsModule::Lsass:
        CommandLsass();
        break;
    case CredsModule::Sam:
        CommandSam();
        break;
    case CredsModule::Lsa:
        CommandLsa();
        break;
    case CredsModule::Dpapi:
        CommandDpapi();
        break;
    case CredsModule::Ntlm:
        CommandNtlm();
        break;
    case CredsModule::Kerberos:
        CommandKerberos();
        break;
    default:
        std::printf("[-] No creds module selected.\n\n");
        break;
    }
}

static void RunSessionModule(Target* target, CliState* cli, SessionModule module) {
    switch (module) {
    case SessionModule::Module:
        HandleSessionModuleCommand(target, cli);
        break;
    case SessionModule::Workspace:
        HandleSessionWorkspaceCommand(target, cli);
        break;
    case SessionModule::Reset:
        HandleSessionResetCommand(target, cli);
        break;
    case SessionModule::Show:
        HandleSessionShowCommand(target, cli);
        break;
    default:
        std::printf("[-] No session module selected.\n\n");
        break;
    }
}

static void RunConfigModule(CliState* cli, ConfigModule module) {
    if (cli == nullptr) return;

    switch (module) {
    case ConfigModule::Verbose:
        cli->verbose = !cli->verbose;
        std::printf("Verbose mode: %s\n\n", cli->verbose ? "on" : "off");
        break;
    case ConfigModule::Timeout:
    case ConfigModule::Output:
    case ConfigModule::Logging:
        std::printf("[framework] Config module selected, but runtime logic is not implemented yet.\n\n");
        break;
    default:
        std::printf("[-] No config module selected.\n\n");
        break;
    }
}

static bool HandlePersistencePath(Target* target, const std::string& command, const char* args) {
    if (command == "persistence/hidden-task") {
        char taskName[128] = { 0 };
        char exePath[256] = { 0 };
        if (ParseTwoArgs(args, taskName, sizeof(taskName), exePath, sizeof(exePath))) {
            CommandCreateScheduledTask(target, taskName, exePath);
        }
        else {
            std::printf("Usage: persistence/hidden-task <taskname> <exepath>\n\n");
        }
        return true;
    }

    if (command == "persistence/reg-autorun") {
        char valName[128] = { 0 };
        char data[256] = { 0 };
        if (ParseTwoArgs(args, valName, sizeof(valName), data, sizeof(data))) {
            CommandSetRegistryAutoRun(nullptr, valName, data);
        }
        else {
            std::printf("Usage: persistence/reg-autorun <valuename> <data>\n\n");
        }
        return true;
    }

    if (command == "persistence/certutil-download") {
        char url[256] = { 0 };
        char dest[256] = { 0 };
        if (ParseTwoArgs(args, url, sizeof(url), dest, sizeof(dest))) {
            CommandSignedProxyCertutil(url, dest);
        }
        else {
            std::printf("Usage: persistence/certutil-download <url> <destfile>\n\n");
        }
        return true;
    }

    return false;
}

static bool HandleDirectPathCommand(Target* target, CliState* cli, const char* input) {
    std::string command;
    const char* args = nullptr;
    SplitCommandAndArgs(input, command, args);

    if (command.find('/') == std::string::npos) {
        return false;
    }

    if (command == "core/help") {
        PrintHelp();
        return true;
    }
    if (command == "core/status") {
        PrintStatus(target, cli);
        return true;
    }
    if (command == "core/version") {
        std::printf("BreakingRoot %s\n\n", VERSION);
        return true;
    }
    if (command == "core/clear") {
        system("cls");
        return true;
    }
    if (command == "core/banner") {
        PrintBanner();
        return true;
    }
    if (command == "core/exit") {
        std::printf("Goodbye...\n");
        std::exit(0);
    }

    if (command == "recon/hostinfo") {
        RunReconModule(ReconModule::HostInfo);
        return true;
    }
    if (command == "recon/osinfo") {
        RunReconModule(ReconModule::OsInfo);
        return true;
    }
    if (command == "recon/userenum") {
        RunReconModule(ReconModule::UserEnum);
        return true;
    }
    if (command == "recon/groupenum") {
        RunReconModule(ReconModule::GroupEnum);
        return true;
    }
    if (command == "recon/shareenum") {
        RunReconModule(ReconModule::ShareEnum);
        return true;
    }
    if (command == "recon/serviceenum") {
        RunReconModule(ReconModule::ServiceEnum);
        return true;
    }
    if (command == "recon/sessionenum") {
        RunReconModule(ReconModule::SessionEnum);
        return true;
    }

    if (command == "defense/recon-all") {
        CommandRecon(&defenseStatus);
        return true;
    }

    if (command == "evasion/bypass") {
        CommandBypassAmsiEtw();
        return true;
    }

    if (command == "creds/lsass") {
        RunCredsModule(CredsModule::Lsass);
        return true;
    }
    if (command == "creds/sam") {
        RunCredsModule(CredsModule::Sam);
        return true;
    }
    if (command == "creds/lsa") {
        RunCredsModule(CredsModule::Lsa);
        return true;
    }
    if (command == "creds/dpapi") {
        RunCredsModule(CredsModule::Dpapi);
        return true;
    }
    if (command == "creds/ntlm") {
        RunCredsModule(CredsModule::Ntlm);
        return true;
    }
    if (command == "creds/kerberos") {
        RunCredsModule(CredsModule::Kerberos);
        return true;
    }

    if (HandlePersistencePath(target, command, args)) {
        return true;
    }

    if (command == "session/module") {
        RunSessionModule(target, cli, SessionModule::Module);
        return true;
    }
    if (command == "session/workspace") {
        RunSessionModule(target, cli, SessionModule::Workspace);
        return true;
    }
    if (command == "session/reset") {
        RunSessionModule(target, cli, SessionModule::Reset);
        return true;
    }
    if (command == "session/show") {
        RunSessionModule(target, cli, SessionModule::Show);
        return true;
    }

    if (command == "config/verbose") {
        RunConfigModule(cli, ConfigModule::Verbose);
        return true;
    }
    if (command == "config/timeout") {
        RunConfigModule(cli, ConfigModule::Timeout);
        return true;
    }
    if (command == "config/output") {
        RunConfigModule(cli, ConfigModule::Output);
        return true;
    }
    if (command == "config/logging") {
        RunConfigModule(cli, ConfigModule::Logging);
        return true;
    }

    std::printf("Unknown module path: %s\n", command.c_str());
    std::printf("Type 'help' or press Tab to see available paths.\n\n");
    return true;
}

static void HandleUseCommand(CliState* cli, const char* arg) {
    if (cli == nullptr || IsBlank(arg)) {
        std::printf("Usage: use <domain|module>\n\n");
        return;
    }

    if (cli->context == CliContext::Root) {
        if (std::strcmp(arg, "core") == 0) {
            cli->context = CliContext::Domain;
            cli->currentDomain = ModuleDomain::Core;
        }
        else if (std::strcmp(arg, "recon") == 0) {
            cli->context = CliContext::Domain;
            cli->currentDomain = ModuleDomain::Recon;
        }
        else if (std::strcmp(arg, "creds") == 0) {
            cli->context = CliContext::Domain;
            cli->currentDomain = ModuleDomain::Creds;
        }
        else if (std::strcmp(arg, "session") == 0) {
            cli->context = CliContext::Domain;
            cli->currentDomain = ModuleDomain::Session;
        }
        else if (std::strcmp(arg, "config") == 0) {
            cli->context = CliContext::Domain;
            cli->currentDomain = ModuleDomain::Config;
        }
        else {
            std::printf("Unknown domain: %s\n\n", arg);
            return;
        }
        ClearSelectedModule(cli);
        std::printf("Entered domain: %s\n\n", arg);
        return;
    }

    if (cli->context == CliContext::Domain) {
        switch (cli->currentDomain) {
        case ModuleDomain::Recon:
            if (std::strcmp(arg, "hostinfo") == 0) cli->currentRecon = ReconModule::HostInfo;
            else if (std::strcmp(arg, "osinfo") == 0) cli->currentRecon = ReconModule::OsInfo;
            else if (std::strcmp(arg, "userenum") == 0) cli->currentRecon = ReconModule::UserEnum;
            else if (std::strcmp(arg, "groupenum") == 0) cli->currentRecon = ReconModule::GroupEnum;
            else if (std::strcmp(arg, "shareenum") == 0) cli->currentRecon = ReconModule::ShareEnum;
            else if (std::strcmp(arg, "serviceenum") == 0) cli->currentRecon = ReconModule::ServiceEnum;
            else if (std::strcmp(arg, "sessionenum") == 0) cli->currentRecon = ReconModule::SessionEnum;
            else {
                std::printf("Unknown recon module: %s\n\n", arg);
                return;
            }
            cli->context = CliContext::Module;
            std::printf("Selected module: recon/%s\n\n", arg);
            return;

        case ModuleDomain::Creds:
            if (std::strcmp(arg, "lsass") == 0) cli->currentCreds = CredsModule::Lsass;
            else if (std::strcmp(arg, "sam") == 0) cli->currentCreds = CredsModule::Sam;
            else if (std::strcmp(arg, "lsa") == 0) cli->currentCreds = CredsModule::Lsa;
            else if (std::strcmp(arg, "dpapi") == 0) cli->currentCreds = CredsModule::Dpapi;
            else if (std::strcmp(arg, "ntlm") == 0) cli->currentCreds = CredsModule::Ntlm;
            else if (std::strcmp(arg, "kerberos") == 0) cli->currentCreds = CredsModule::Kerberos;
            else {
                std::printf("Unknown creds module: %s\n\n", arg);
                return;
            }
            cli->context = CliContext::Module;
            std::printf("Selected module: creds/%s\n\n", arg);
            return;

        case ModuleDomain::Session:
            if (std::strcmp(arg, "module") == 0) cli->currentSession = SessionModule::Module;
            else if (std::strcmp(arg, "workspace") == 0) cli->currentSession = SessionModule::Workspace;
            else if (std::strcmp(arg, "reset") == 0) cli->currentSession = SessionModule::Reset;
            else if (std::strcmp(arg, "show") == 0) cli->currentSession = SessionModule::Show;
            else {
                std::printf("Unknown session module: %s\n\n", arg);
                return;
            }
            cli->context = CliContext::Module;
            std::printf("Selected module: session/%s\n\n", arg);
            return;

        case ModuleDomain::Config:
            if (std::strcmp(arg, "verbose") == 0) cli->currentConfig = ConfigModule::Verbose;
            else if (std::strcmp(arg, "timeout") == 0) cli->currentConfig = ConfigModule::Timeout;
            else if (std::strcmp(arg, "output") == 0) cli->currentConfig = ConfigModule::Output;
            else if (std::strcmp(arg, "logging") == 0) cli->currentConfig = ConfigModule::Logging;
            else {
                std::printf("Unknown config module: %s\n\n", arg);
                return;
            }
            cli->context = CliContext::Module;
            std::printf("Selected module: config/%s\n\n", arg);
            return;

        default:
            std::printf("This domain has no nested modules.\n\n");
            return;
        }
    }
    std::printf("Already inside a module. Use 'back' first.\n\n");
}

static void HandleBackCommand(CliState* cli) {
    if (cli == nullptr) return;
    if (cli->context == CliContext::Module) {
        cli->context = CliContext::Domain;
        ClearSelectedModule(cli);
        std::printf("Returned to domain context.\n\n");
    }
    else if (cli->context == CliContext::Domain) {
        cli->context = CliContext::Root;
        cli->currentDomain = ModuleDomain::None;
        ClearSelectedModule(cli);
        std::printf("Returned to root context.\n\n");
    }
    else {
        std::printf("Already at root context.\n\n");
    }
}

static void HandleListCommand(const CliState* cli) {
    if (cli == nullptr) return;
    if (cli->context == CliContext::Root) {
        std::printf("Domains:\n  core\n  recon\n  defense\n  evasion\n  creds\n  persistence\n  session\n  config\n\n");
        std::printf("Direct path examples:\n  recon/userenum\n  creds/dpapi\n  defense/recon-all\n  config/verbose\n\n");
        return;
    }
    if (cli->context == CliContext::Domain) {
        switch (cli->currentDomain) {
        case ModuleDomain::Core:   std::printf("Core modules:\n  help\n  exit\n  clear\n  version\n  banner\n\n"); return;
        case ModuleDomain::Recon:  std::printf("Recon modules:\n  hostinfo\n  osinfo\n  userenum\n  groupenum\n  shareenum\n  serviceenum\n  sessionenum\n\n"); return;
        case ModuleDomain::Creds:  std::printf("Creds modules:\n  lsass\n  sam\n  lsa\n  dpapi\n  ntlm\n  kerberos\n\n"); return;
        case ModuleDomain::Session: std::printf("Session modules:\n  module\n  workspace\n  reset\n  show\n\n"); return;
        case ModuleDomain::Config: std::printf("Config modules:\n  verbose\n  timeout\n  output\n  logging\n\n"); return;
        default: break;
        }
    }
    std::printf("A module is already selected.\n\n");
}

static void HandleShowCommand(const CliState* cli) {
    if (cli == nullptr) return;
    if (cli->context == CliContext::Root) std::printf("Current context: root\n\n");
    else if (cli->context == CliContext::Domain) std::printf("Current domain selected.\n\n");
    else if (cli->context == CliContext::Module) std::printf("Module selected and ready.\n\n");
}

static void HandleRunCommand(Target* target, CliState* cli) {
    if (target == nullptr || cli == nullptr) return;
    if (cli->context != CliContext::Module) {
        std::printf("No module selected.\n\n");
        return;
    }

    switch (cli->currentDomain) {
    case ModuleDomain::Recon:
        RunReconModule(cli->currentRecon);
        return;

    case ModuleDomain::Creds:
        RunCredsModule(cli->currentCreds);
        return;

    case ModuleDomain::Session:
        RunSessionModule(target, cli, cli->currentSession);
        return;

    case ModuleDomain::Config:
        RunConfigModule(cli, cli->currentConfig);
        return;

    default:
        std::printf("No runnable handler for this domain.\n\n");
        return;
    }
}

static CommandType GetCommandType(const char* input) {
    if (input == nullptr) return CommandType::Unknown;

    if (std::strcmp(input, "help") == 0)          return CommandType::Help;
    if (std::strcmp(input, "exit") == 0)          return CommandType::Exit;
    if (std::strcmp(input, "status") == 0)        return CommandType::Status;
    if (std::strcmp(input, "back") == 0)          return CommandType::Back;
    if (std::strcmp(input, "list") == 0)          return CommandType::List;
    if (std::strcmp(input, "show") == 0)          return CommandType::Show;
    if (std::strcmp(input, "run") == 0)           return CommandType::Run;
    if (std::strcmp(input, "lsass") == 0)         return CommandType::Lsass;
    if (std::strncmp(input, "reg-autorun ", 12) == 0) return CommandType::RegistryAutoRunSet;
    if (std::strncmp(input, "proxy-certutil ", 15) == 0) return CommandType::ProxyCertutil;

    if (std::strncmp(input, "use ", 4) == 0)           return CommandType::Use;
    if (std::strncmp(input, "ps-encode ", 10) == 0)    return CommandType::PowerShellEncoded;
    if (std::strncmp(input, "schtask-create ", 15) == 0) return CommandType::ScheduledTaskCreate;

    if (std::strcmp(input, "version") == 0) return CommandType::CmdVersion;
    if (std::strcmp(input, "clear") == 0) return CommandType::CmdClear;
    if (std::strcmp(input, "banner") == 0) return CommandType::CmdBanner;

    if (std::strcmp(input, "recon-all") == 0) return CommandType::ReconAll;
    if (std::strcmp(input, "bypass") == 0) return CommandType::BypassAMSIETW;

    if (std::strcmp(input, "sam") == 0) return CommandType::CmdSam;
    if (std::strcmp(input, "lsa") == 0) return CommandType::CmdLsa;
    if (std::strcmp(input, "dpapi") == 0) return CommandType::CmdDpapi;
    if (std::strcmp(input, "ntlm") == 0) return CommandType::CmdNtlm;
    if (std::strcmp(input, "kerberos") == 0) return CommandType::CmdKerberos;

    if (std::strcmp(input, "module") == 0) return CommandType::CmdSessionModule;
    if (std::strcmp(input, "workspace") == 0) return CommandType::CmdSessionWorkspace;
    if (std::strcmp(input, "reset") == 0) return CommandType::CmdSessionReset;

    return CommandType::Unknown;
}

void ParseCommand(Target* target, CliState* cli, const char* input) {
    if (target == nullptr || cli == nullptr || input == nullptr) return;

    if (HandleDirectPathCommand(target, cli, input)) {
        return;
    }

    switch (GetCommandType(input)) {
    case CommandType::Help:
        PrintHelp();
        break;
    case CommandType::Exit:
        std::printf("Goodbye...\n");
        std::exit(0);
        break;
    case CommandType::Status:
        PrintStatus(target, cli);
        break;
    case CommandType::Use:
        HandleUseCommand(cli, GetArgumentAfterPrefix(input, 4));
        break;
    case CommandType::Back:
        HandleBackCommand(cli);
        break;
    case CommandType::List:
        HandleListCommand(cli);
        break;
    case CommandType::Show:
        HandleShowCommand(cli);
        break;
    case CommandType::Run:
        HandleRunCommand(target, cli);
        break;
    case CommandType::CmdVersion:
        std::printf("BreakingRoot %s\n\n", VERSION);
        break;
    case CommandType::CmdClear:
        system("cls");
        break;
    case CommandType::CmdBanner:
        PrintBanner();
        break;
    case CommandType::PowerShellEncoded:
        CommandPowerShellEncoded(target, cli, GetArgumentAfterPrefix(input, 10));
        break;
    case CommandType::ScheduledTaskCreate:
    {
        const char* args = GetArgumentAfterPrefix(input, 15);
        char taskName[128] = { 0 }, exePath[256] = { 0 };
        if (ParseTwoArgs(args, taskName, sizeof(taskName), exePath, sizeof(exePath))) {
            CommandCreateScheduledTask(target, taskName, exePath);
        }
        else {
            std::printf("Usage: schtask-create <taskname> <exepath>\n\n");
        }
    }
    break;
    case CommandType::RegistryAutoRunSet:
    {
        const char* args = GetArgumentAfterPrefix(input, 12);
        char valName[128] = { 0 }, data[256] = { 0 };
        if (ParseTwoArgs(args, valName, sizeof(valName), data, sizeof(data))) {
            CommandSetRegistryAutoRun(nullptr, valName, data);
        }
        else {
            std::printf("Usage: reg-autorun <valuename> <data>\n\n");
        }
    }
    break;
    case CommandType::ProxyCertutil:
    {
        const char* args = GetArgumentAfterPrefix(input, 15);
        char url[256] = { 0 }, dest[256] = { 0 };
        if (ParseTwoArgs(args, url, sizeof(url), dest, sizeof(dest))) {
            CommandSignedProxyCertutil(url, dest);
        }
        else {
            std::printf("Usage: proxy-certutil <url> <destfile>\n\n");
        }
    }
    break;
    case CommandType::ReconAll:
        CommandRecon(&defenseStatus);
        break;
    case CommandType::BypassAMSIETW:
        CommandBypassAmsiEtw();
        break;
    case CommandType::Lsass:
        CommandLsass();
        break;
    case CommandType::CmdSam:
        CommandSam();
        break;
    case CommandType::CmdLsa:
        CommandLsa();
        break;
    case CommandType::CmdDpapi:
        CommandDpapi();
        break;
    case CommandType::CmdNtlm:
        CommandNtlm();
        break;
    case CommandType::CmdKerberos:
        CommandKerberos();
        break;
    case CommandType::CmdSessionModule:
        HandleSessionModuleCommand(target, cli);
        break;
    case CommandType::CmdSessionWorkspace:
        HandleSessionWorkspaceCommand(target, cli);
        break;
    case CommandType::CmdSessionReset:
        HandleSessionResetCommand(target, cli);
        break;
    case CommandType::Unknown:
    default:
        std::printf("Unknown command. Type 'help'.\n\n");
        break;
    }
}

static const std::vector<std::string>& GetCompletionDictionary() {
    static const std::vector<std::string> commands = {
        "help", "exit", "status", "list", "show", "run", "back", "version", "clear", "banner",
        "use", "use core", "use recon", "use creds", "use session", "use config",
        "recon/hostinfo", "recon/osinfo", "recon/userenum", "recon/groupenum", "recon/shareenum", "recon/serviceenum", "recon/sessionenum",
        "defense/recon-all",
        "evasion/bypass",
        "creds/lsass", "creds/sam", "creds/lsa", "creds/dpapi", "creds/ntlm", "creds/kerberos",
        "persistence/hidden-task", "persistence/reg-autorun", "persistence/certutil-download",
        "session/module", "session/workspace", "session/reset", "session/show",
        "config/verbose", "config/timeout", "config/output", "config/logging",
        "lsass", "sam", "lsa", "dpapi", "ntlm", "kerberos", "recon-all", "bypass",
        "ps-encode", "schtask-create", "reg-autorun", "proxy-certutil"
    };
    return commands;
}

static std::vector<std::string> FindCompletionMatches(const char* prefix) {
    std::vector<std::string> matches;
    if (prefix == nullptr) return matches;

    const std::string prefixLower = ToLowerAscii(prefix);
    const auto& dictionary = GetCompletionDictionary();

    for (const std::string& candidate : dictionary) {
        if (candidate.rfind(prefixLower, 0) == 0) {
            matches.push_back(candidate);
        }
    }
    return matches;
}

#ifdef _WIN32
static void RedrawInputLine(const char* prompt, const char* buffer, std::size_t previousVisibleLength) {
    const std::size_t promptLength = prompt ? std::strlen(prompt) : 0;
    const std::size_t bufferLength = buffer ? std::strlen(buffer) : 0;
    const std::size_t currentVisibleLength = promptLength + bufferLength;

    std::printf("\r%s%s", prompt ? prompt : "", buffer ? buffer : "");

    if (previousVisibleLength > currentVisibleLength) {
        for (std::size_t i = 0; i < previousVisibleLength - currentVisibleLength; ++i) {
            std::printf(" ");
        }
        std::printf("\r%s%s", prompt ? prompt : "", buffer ? buffer : "");
    }
    std::fflush(stdout);
}
#endif

bool ReadCommandLine(const char* prompt, char* buffer, std::size_t bufferSize) {
    if (buffer == nullptr || bufferSize == 0) return false;

    buffer[0] = '\0';

#ifndef _WIN32
    std::printf("%s", prompt ? prompt : "");
    if (std::fgets(buffer, static_cast<int>(bufferSize), stdin) == nullptr) {
        return false;
    }
    buffer[std::strcspn(buffer, "\r\n")] = '\0';
    return true;
#else
    std::size_t length = 0;
    std::size_t previousVisibleLength = prompt ? std::strlen(prompt) : 0;
    bool completionActive = false;
    std::string completionPrefix;
    std::vector<std::string> matches;
    std::size_t nextMatchIndex = 0;

    std::printf("%s", prompt ? prompt : "");
    std::fflush(stdout);

    while (true) {
        const int ch = _getch();

        if (ch == 3) { // Ctrl+C
            std::printf("^C\n");
            buffer[0] = '\0';
            return false;
        }

        if (ch == 13) { // Enter
            std::printf("\n");
            buffer[length] = '\0';
            return true;
        }

        if (ch == 8) { // Backspace
            if (length > 0) {
                buffer[--length] = '\0';
                completionActive = false;
                completionPrefix.clear();
                matches.clear();
                nextMatchIndex = 0;
                RedrawInputLine(prompt, buffer, previousVisibleLength);
                previousVisibleLength = (prompt ? std::strlen(prompt) : 0) + length;
            }
            continue;
        }

        if (ch == 9) { // Tab
            if (!completionActive) {
                completionPrefix.assign(buffer);
                matches = FindCompletionMatches(completionPrefix.c_str());
                nextMatchIndex = 0;
                completionActive = true;
            }

            if (!matches.empty()) {
                const std::string& completion = matches[nextMatchIndex];
                std::snprintf(buffer, bufferSize, "%s", completion.c_str());
                length = std::strlen(buffer);
                nextMatchIndex = (nextMatchIndex + 1) % matches.size();
                RedrawInputLine(prompt, buffer, previousVisibleLength);
                previousVisibleLength = (prompt ? std::strlen(prompt) : 0) + length;
            }
            else {
                std::printf("\a");
                std::fflush(stdout);
            }
            continue;
        }

        if (ch == 0 || ch == 224) {
            _getch();
            continue;
        }

        if (std::isprint(static_cast<unsigned char>(ch)) && length + 1 < bufferSize) {
            buffer[length++] = static_cast<char>(ch);
            buffer[length] = '\0';
            completionActive = false;
            completionPrefix.clear();
            matches.clear();
            nextMatchIndex = 0;
            std::printf("%c", ch);
            std::fflush(stdout);
            previousVisibleLength = (prompt ? std::strlen(prompt) : 0) + length;
        }
    }
#endif
}
