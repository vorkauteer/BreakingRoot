#pragma once
#include "common.h"
#include "defense.h"

void CommandRecon(DefenseStatus* ds);
void CommandBypassAmsiEtw();
void CommandLsass();

void InitApp(Target* target, CliState* cli);
void BuildPrompt(const CliState* cli, char* line, std::size_t lineSize);

void PrintBanner();
void PrintHelp();
void PrintStatus(const Target* target, const CliState* cli);

void CommandLsassAccess(Target* target, CliState* cli);
void CommandPowerShellEncoded(Target* target, CliState* cli, const char* command);
void CommandCreateScheduledTask(Target* target, const char* taskName, const char* exePath);
void CommandSetRegistryAutoRun(const char* keyPath, const char* valueName, const char* data);
void CommandSignedProxyCertutil(const char* sourceUrl, const char* destFile);

bool IsBlank(const char* text);

void CommandSam();
void CommandLsa();
void CommandDpapi();
void CommandNtlm();
void CommandKerberos();
void CommandGetSystem();

void HandleSessionModuleCommand(Target* target, CliState* cli);
void HandleSessionWorkspaceCommand(Target* target, CliState* cli);
void HandleSessionResetCommand(Target* target, CliState* cli);
void HandleSessionShowCommand(Target* target, CliState* cli);