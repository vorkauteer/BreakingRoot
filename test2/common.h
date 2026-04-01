#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <cstddef>

constexpr auto VERSION = "v1.0-test";
constexpr std::size_t MAX_INPUT = 1024;
constexpr std::size_t MAX_PROMPT = 256;
constexpr std::size_t MAX_HOST = 128;
constexpr std::size_t MAX_PORT_STR = 16;
constexpr std::size_t MAX_USERNAME = 128;
constexpr std::size_t MAX_PASSWORD = 128;
constexpr std::size_t MAX_DOMAIN = 128;
constexpr int DEFAULT_PORT = 0;

enum class ModuleDomain {
    None = 0,
    Core,
    Target,
    Recon,
    Creds,
    Session,
    Config
};

enum class ReconModule {
    None = 0,
    HostInfo,
    OsInfo,
    UserEnum,
    GroupEnum,
    ShareEnum,
    ServiceEnum,
    SessionEnum
};

enum class CredsModule {
    None = 0,
    Lsass,
    Sam,
    Lsa,
    Dpapi,
    Ntlm,
    Kerberos
};

enum class SessionModule {
    None = 0,
    Module,
    Workspace,
    Reset,
    Show
};

enum class ConfigModule {
    None = 0,
    Verbose,
    Timeout,
    Output,
    Logging
};

enum class CliContext {
    Root = 0,
    Domain,
    Module
};

struct Target {
    char host[MAX_HOST];
    int port;
    char username[MAX_USERNAME];
    char password[MAX_PASSWORD];
    char domain[MAX_DOMAIN];
};

struct CliState {
    CliContext context{ CliContext::Root };
    ModuleDomain currentDomain{ ModuleDomain::None };

    ReconModule currentRecon{ ReconModule::None };
    CredsModule currentCreds{ CredsModule::None };
    SessionModule currentSession{ SessionModule::None };
    ConfigModule currentConfig{ ConfigModule::None };

    bool verbose{ false };
};