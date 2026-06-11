#pragma once

#include "common.h"

void ParseCommand(Target* target, CliState* cli, const char* input);
bool ReadCommandLine(const char* prompt, char* buffer, std::size_t bufferSize);
