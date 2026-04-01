#include "app.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

static const char* DomainToString(ModuleDomain domain) {
    switch (domain) {
    case ModuleDomain::Core:    return "core";
    case ModuleDomain::Target:  return "target";
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

    target->host[0] = '\0';
    target->username[0] = '\0';
    target->password[0] = '\0';
    target->domain[0] = '\0';
    target->port = DEFAULT_PORT;

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
    std::printf("BreakingRoot %s (ITSecurity)\n", VERSION);
    std::printf("Modular Framework Console\n");
    std::printf("Type 'help' to list commands\n\n");
}

void PrintHelp() {
    std::printf("Core commands:\n");
    std::printf("  help                 - show help\n");
    std::printf("  exit                 - quit\n");
    std::printf("  status               - show framework state\n");
    std::printf("  list                 - list domains or modules\n");
    std::printf("  use <name>           - enter domain or module\n");
    std::printf("  back                 - return to previous level\n");
    std::printf("  show                 - show selected module\n");
    std::printf("  run                  - execute selected module handler\n");
    std::printf("\n");
    std::printf("Target commands:\n");
    std::printf("  host <value>\n");
    std::printf("  port <value>\n");
    std::printf("  username <value>\n");
    std::printf("  password <value>\n");
    std::printf("  domain <value>\n");
    std::printf("  clear-target\n\n");
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

    std::printf("Host    : %s\n", IsBlank(target->host) ? "<unset>" : target->host);
    std::printf("Port    : %d\n", target->port);
    std::printf("User    : %s\n", IsBlank(target->username) ? "<unset>" : target->username);
    std::printf("Domain  : %s\n", IsBlank(target->domain) ? "<unset>" : target->domain);
    std::printf("\n");
}

void CommandSetTargetHost(Target* target, const char* value) {
    if (target == nullptr || IsBlank(value)) {
        std::printf("Invalid host value.\n\n");
        return;
    }

    std::snprintf(target->host, sizeof(target->host), "%s", value);
    std::printf("Host set: %s\n\n", target->host);
}

void CommandSetTargetPort(Target* target, const char* value) {
    if (target == nullptr || IsBlank(value)) {
        std::printf("Invalid port value.\n\n");
        return;
    }

    char* endptr = nullptr;
    const long port = std::strtol(value, &endptr, 10);

    if (*value == '\0' || *endptr != '\0' || port < 0 || port > 65535) {
        std::printf("Invalid port.\n\n");
        return;
    }

    target->port = static_cast<int>(port);
    std::printf("Port set: %d\n\n", target->port);
}

void CommandSetTargetUsername(Target* target, const char* value) {
    if (target == nullptr || IsBlank(value)) {
        std::printf("Invalid username value.\n\n");
        return;
    }

    std::snprintf(target->username, sizeof(target->username), "%s", value);
    std::printf("Username applied.\n\n");
}

void CommandSetTargetPassword(Target* target, const char* value) {
    if (target == nullptr || IsBlank(value)) {
        std::printf("Invalid password value.\n\n");
        return;
    }

    std::snprintf(target->password, sizeof(target->password), "%s", value);
    std::printf("Password applied.\n\n");
}

void CommandSetTargetDomain(Target* target, const char* value) {
    if (target == nullptr || IsBlank(value)) {
        std::printf("Invalid domain value.\n\n");
        return;
    }

    std::snprintf(target->domain, sizeof(target->domain), "%s", value);
    std::printf("Domain applied: %s\n\n", target->domain);
}

void CommandClearTarget(Target* target) {
    if (target == nullptr) {
        return;
    }

    target->host[0] = '\0';
    target->username[0] = '\0';
    target->password[0] = '\0';
    target->domain[0] = '\0';
    target->port = DEFAULT_PORT;

    std::printf("Target state cleared.\n\n");
}