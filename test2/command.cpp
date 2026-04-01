#include "command.h"
#include "app.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

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
    Host,
    Port,
    Username,
    Password,
    Domain,
    ClearTarget,
    Unknown
};

static CommandType GetCommandType(const char* input);

static void ClearSelectedModule(CliState* cli) {
    if (cli == nullptr) {
        return;
    }

    cli->currentRecon = ReconModule::None;
    cli->currentCreds = CredsModule::None;
    cli->currentSession = SessionModule::None;
    cli->currentConfig = ConfigModule::None;
}

static const char* GetArgumentAfterPrefix(const char* input, std::size_t prefixLength) {
    if (input == nullptr) {
        return nullptr;
    }

    const char* arg = input + prefixLength;
    return (*arg == '\0') ? nullptr : arg;
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
        else if (std::strcmp(arg, "target") == 0) {
            cli->context = CliContext::Domain;
            cli->currentDomain = ModuleDomain::Target;
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
            if (std::strcmp(arg, "hostinfo") == 0) {
                cli->currentRecon = ReconModule::HostInfo;
            }
            else if (std::strcmp(arg, "osinfo") == 0) {
                cli->currentRecon = ReconModule::OsInfo;
            }
            else if (std::strcmp(arg, "userenum") == 0) {
                cli->currentRecon = ReconModule::UserEnum;
            }
            else if (std::strcmp(arg, "groupenum") == 0) {
                cli->currentRecon = ReconModule::GroupEnum;
            }
            else if (std::strcmp(arg, "shareenum") == 0) {
                cli->currentRecon = ReconModule::ShareEnum;
            }
            else if (std::strcmp(arg, "serviceenum") == 0) {
                cli->currentRecon = ReconModule::ServiceEnum;
            }
            else if (std::strcmp(arg, "sessionenum") == 0) {
                cli->currentRecon = ReconModule::SessionEnum;
            }
            else {
                std::printf("Unknown recon module: %s\n\n", arg);
                return;
            }
            cli->context = CliContext::Module;
            std::printf("Selected module: recon/%s\n\n", arg);
            return;

        case ModuleDomain::Creds:
            if (std::strcmp(arg, "lsass") == 0) {
                cli->currentCreds = CredsModule::Lsass;
            }
            else if (std::strcmp(arg, "sam") == 0) {
                cli->currentCreds = CredsModule::Sam;
            }
            else if (std::strcmp(arg, "lsa") == 0) {
                cli->currentCreds = CredsModule::Lsa;
            }
            else if (std::strcmp(arg, "dpapi") == 0) {
                cli->currentCreds = CredsModule::Dpapi;
            }
            else if (std::strcmp(arg, "ntlm") == 0) {
                cli->currentCreds = CredsModule::Ntlm;
            }
            else if (std::strcmp(arg, "kerberos") == 0) {
                cli->currentCreds = CredsModule::Kerberos;
            }
            else {
                std::printf("Unknown creds module: %s\n\n", arg);
                return;
            }
            cli->context = CliContext::Module;
            std::printf("Selected module: creds/%s\n\n", arg);
            return;

        case ModuleDomain::Session:
            if (std::strcmp(arg, "module") == 0) {
                cli->currentSession = SessionModule::Module;
            }
            else if (std::strcmp(arg, "workspace") == 0) {
                cli->currentSession = SessionModule::Workspace;
            }
            else if (std::strcmp(arg, "reset") == 0) {
                cli->currentSession = SessionModule::Reset;
            }
            else if (std::strcmp(arg, "show") == 0) {
                cli->currentSession = SessionModule::Show;
            }
            else {
                std::printf("Unknown session module: %s\n\n", arg);
                return;
            }
            cli->context = CliContext::Module;
            std::printf("Selected module: session/%s\n\n", arg);
            return;

        case ModuleDomain::Config:
            if (std::strcmp(arg, "verbose") == 0) {
                cli->currentConfig = ConfigModule::Verbose;
            }
            else if (std::strcmp(arg, "timeout") == 0) {
                cli->currentConfig = ConfigModule::Timeout;
            }
            else if (std::strcmp(arg, "output") == 0) {
                cli->currentConfig = ConfigModule::Output;
            }
            else if (std::strcmp(arg, "logging") == 0) {
                cli->currentConfig = ConfigModule::Logging;
            }
            else {
                std::printf("Unknown config module: %s\n\n", arg);
                return;
            }
            cli->context = CliContext::Module;
            std::printf("Selected module: config/%s\n\n", arg);
            return;

        case ModuleDomain::Core:
        case ModuleDomain::Target:
        case ModuleDomain::None:
        default:
            std::printf("This domain has no nested modules.\n\n");
            return;
        }
    }

    std::printf("Already inside a module. Use 'back' first.\n\n");
}

static void HandleBackCommand(CliState* cli) {
    if (cli == nullptr) {
        return;
    }

    if (cli->context == CliContext::Module) {
        cli->context = CliContext::Domain;
        ClearSelectedModule(cli);
        std::printf("Returned to domain context.\n\n");
        return;
    }

    if (cli->context == CliContext::Domain) {
        cli->context = CliContext::Root;
        cli->currentDomain = ModuleDomain::None;
        ClearSelectedModule(cli);
        std::printf("Returned to root context.\n\n");
        return;
    }

    std::printf("Already at root context.\n\n");
}

static void HandleListCommand(const CliState* cli) {
    if (cli == nullptr) {
        return;
    }

    if (cli->context == CliContext::Root) {
        std::printf("Domains:\n");
        std::printf("  core\n");
        std::printf("  target\n");
        std::printf("  recon\n");
        std::printf("  creds\n");
        std::printf("  session\n");
        std::printf("  config\n\n");
        return;
    }

    if (cli->context == CliContext::Domain) {
        switch (cli->currentDomain) {
        case ModuleDomain::Core:
            std::printf("Core modules:\n  help\n  exit\n  clear\n  version\n  banner\n\n");
            return;
        case ModuleDomain::Target:
            std::printf("Target modules:\n  host\n  port\n  username\n  password\n  domain\n  status\n\n");
            return;
        case ModuleDomain::Recon:
            std::printf("Recon modules:\n");
            std::printf("  hostinfo\n  osinfo\n  userenum\n  groupenum\n  shareenum\n  serviceenum\n  sessionenum\n\n");
            return;
        case ModuleDomain::Creds:
            std::printf("Creds modules:\n");
            std::printf("  lsass\n  sam\n  lsa\n  dpapi\n  ntlm\n  kerberos\n\n");
            return;
        case ModuleDomain::Session:
            std::printf("Session modules:\n  module\n  workspace\n  reset\n  show\n\n");
            return;
        case ModuleDomain::Config:
            std::printf("Config modules:\n  verbose\n  timeout\n  output\n  logging\n\n");
            return;
        default:
            break;
        }
    }

    std::printf("A module is already selected.\n\n");
}

static void HandleShowCommand(const CliState* cli) {
    if (cli == nullptr) {
        return;
    }

    if (cli->context == CliContext::Root) {
        std::printf("Current context: root\n\n");
        return;
    }

    if (cli->context == CliContext::Domain) {
        std::printf("Current domain selected.\n\n");
        return;
    }

    if (cli->context == CliContext::Module) {
        std::printf("Module selected and ready.\n\n");
        return;
    }
}

static void HandleRunCommand(Target* target, CliState* cli) {
    if (target == nullptr || cli == nullptr) {
        return;
    }

    if (cli->context != CliContext::Module) {
        std::printf("No module selected.\n\n");
        return;
    }

    switch (cli->currentDomain) {
    case ModuleDomain::Recon:
        std::printf("[framework] Recon module handler invoked.\n\n");
        return;

    case ModuleDomain::Creds:
        std::printf("[framework] Creds module handler invoked.\n");
        std::printf("[framework] Placeholder only. No module logic attached.\n\n");
        return;

    case ModuleDomain::Session:
        if (cli->currentSession == SessionModule::Show) {
            PrintStatus(target, cli);
            return;
        }
        if (cli->currentSession == SessionModule::Reset) {
            InitApp(target, cli);
            std::printf("Framework state reset.\n\n");
            return;
        }
        std::printf("[framework] Session module handler invoked.\n\n");
        return;

    case ModuleDomain::Config:
        if (cli->currentConfig == ConfigModule::Verbose) {
            cli->verbose = !cli->verbose;
            std::printf("Verbose mode: %s\n\n", cli->verbose ? "on" : "off");
            return;
        }
        std::printf("[framework] Config module handler invoked.\n\n");
        return;

    default:
        std::printf("No runnable handler for this domain.\n\n");
        return;
    }
}

static CommandType GetCommandType(const char* input) {
    if (input == nullptr) {
        return CommandType::Unknown;
    }

    if (std::strcmp(input, "help") == 0)         return CommandType::Help;
    if (std::strcmp(input, "exit") == 0)         return CommandType::Exit;
    if (std::strcmp(input, "status") == 0)       return CommandType::Status;
    if (std::strcmp(input, "back") == 0)         return CommandType::Back;
    if (std::strcmp(input, "list") == 0)         return CommandType::List;
    if (std::strcmp(input, "show") == 0)         return CommandType::Show;
    if (std::strcmp(input, "run") == 0)          return CommandType::Run;
    if (std::strcmp(input, "clear-target") == 0) return CommandType::ClearTarget;

    if (std::strncmp(input, "use ", 4) == 0)      return CommandType::Use;
    if (std::strncmp(input, "host ", 5) == 0)     return CommandType::Host;
    if (std::strncmp(input, "port ", 5) == 0)     return CommandType::Port;
    if (std::strncmp(input, "username ", 9) == 0) return CommandType::Username;
    if (std::strncmp(input, "password ", 9) == 0) return CommandType::Password;
    if (std::strncmp(input, "domain ", 7) == 0)   return CommandType::Domain;

    return CommandType::Unknown;
}

void ParseCommand(Target* target, CliState* cli, const char* input) {
    if (target == nullptr || cli == nullptr || input == nullptr) {
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

    case CommandType::Host:
        CommandSetTargetHost(target, GetArgumentAfterPrefix(input, 5));
        break;

    case CommandType::Port:
        CommandSetTargetPort(target, GetArgumentAfterPrefix(input, 5));
        break;

    case CommandType::Username:
        CommandSetTargetUsername(target, GetArgumentAfterPrefix(input, 9));
        break;

    case CommandType::Password:
        CommandSetTargetPassword(target, GetArgumentAfterPrefix(input, 9));
        break;

    case CommandType::Domain:
        CommandSetTargetDomain(target, GetArgumentAfterPrefix(input, 7));
        break;

    case CommandType::ClearTarget:
        CommandClearTarget(target);
        break;

    case CommandType::Unknown:
    case CommandType::None:
    default:
        std::printf("Unknown command. Type 'help'.\n\n");
        break;
    }
}