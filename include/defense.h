#pragma once
#include "common.h"
#include <windows.h>

struct DefenseStatus {
    bool ppLEnabled;
    int pplLevel;
    bool credentialGuard;
    bool hvciEnabled;
    bool secureBoot;
    bool tpmPresent;
    bool testSigning;
    bool amsiActive;
    bool etwActive;
    bool edrPresent;
    wchar_t edrName[128];
};

bool CheckPPL(DefenseStatus* ds);
bool CheckCredentialGuard(DefenseStatus* ds);
bool CheckHVCI(DefenseStatus* ds);
bool CheckSecureBoot();
bool CheckTestSigning();
void DetectEDR(DefenseStatus* ds);
void FullDefenseRecon(DefenseStatus* ds);
void PrintDefenseStatus(const DefenseStatus* ds);