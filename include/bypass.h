#pragma once
#include <windows.h>
#include <winternl.h>

void BypassAmsiViaPatch();
void DisableEtw();

typedef NTSTATUS(NTAPI* pNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
HANDLE SysOpenProcess(DWORD pid, DWORD access);