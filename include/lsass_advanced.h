#pragma once
#include <windows.h>

DWORD GetLsassPid();
bool RemovePPLViaKernel();
bool DumpLsassViaMiniDumpSyscall(DWORD pid, const char* outPath);