#include "common.h"
#include "command.h"


void InitApp(Target* host);

void CommandLine(const Target* host, char* line, size_t lineSize);
void CommandHelp();
void CommandSetTarget(Target* host, const char* target);
void CommandSetPort(Target* host, const char* port);
void CommandSetUsername(Target* host, const char* username);
void CommandSetPassword(Target* host, const char* password);
void CommandStatus(const Target* host);
void CommandClearTarget(Target* host);

int check_ipv4(const char* data);
int check_port(const char* data);
