#pragma once

#include "common.h"

void InitApp(Target* target, CliState* cli);
void BuildPrompt(const CliState* cli, char* line, std::size_t lineSize);

void PrintBanner();
void PrintHelp();
void PrintStatus(const Target* target, const CliState* cli);

void CommandSetTargetHost(Target* target, const char* value);
void CommandSetTargetPort(Target* target, const char* value);
void CommandSetTargetUsername(Target* target, const char* value);
void CommandSetTargetPassword(Target* target, const char* value);
void CommandSetTargetDomain(Target* target, const char* value);
void CommandClearTarget(Target* target);

bool IsBlank(const char* text);