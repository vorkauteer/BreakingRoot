#include "app.h"
#include "common.h"

#include <cstdio>
#include <cstring>
#include <cctype>
#include <cstdlib>

void InitApp(Target* host) {
	if (host == nullptr) {
		return;
	}

	host->address[0] = '\0';
	host->username[0] = '\0';
	host->password[0] = '\0';
	host->port = DEFAULT_PORT;
}

void CommandLine(const Target* host, char* line, size_t lineSize) {
	if (host == nullptr || line == nullptr || lineSize == 0) return;
	if (host->state == (DISCONNECTED)) {
		std::snprintf(line, lineSize, "[%s]itsecsoft> ", VERSION);
	}
	else if (host->state == CONNECTED){
		std::snprintf(line, lineSize, "[%s]itsecsoft(%s)> ", VERSION , host->address);
	}
}

void CommandHelp() {
	std::printf("Commands:\n");
	std::printf("  help                - show help\n");
	std::printf("  target <host>       - set target host\n");
	std::printf("  port <number>       - set target port\n");
	std::printf("  clear-target        - clear selected target\n");
	std::printf("  connect             - connect to target\n");
	std::printf("  disconnect          - disconnect session\n");
	std::printf("  status              - show current status\n");
	std::printf("  module <name>       - run PowerShell module from modules\\<name>.ps1\n");
	std::printf("  exit                - quit\n");
	std::printf("\n");
	std::printf("After connect, any unknown input is sent to the TCP peer.\n");
}

void CommandSetTarget(Target* host, const char* target) {
	if (host == nullptr || target == nullptr) {
		return;
	}

	if (host->state == CONNECTED) {
		std::printf("Disconnect first.\n");
		return;
	}

	if (check_ipv4(target)) {
		strncpy_s(host->address, target, sizeof(host->address) - 1);
		host->address[sizeof(host->address) - 1] = '\0';
		std::printf("Target selected: %s\n", host->address);
	}
	else {
		std::printf("Invalid target address\n");
	}
}

void CommandSetPort(Target* host, const char* data) {
	if (host == nullptr || data == nullptr) {
		return;
	}

	if (host->state == CONNECTED) {
		std::printf("Disconnect first.\n");
		return;
	}

	char* endptr = nullptr;
	const long port = std::strtol(data, &endptr, 10);

	if (*data == '\0' || *endptr != '\0' || port < 1 || port > 65535) {
		std::printf("Invalid port.\n");
		return;
	}

	host->port = static_cast<int>(port);
	std::printf("Port set to: %d\n", host->port);
}

void CommandSetUsername(Target* host, const char* username) {
	std::strncpy(host->username, username, sizeof(host->username) - 1);
	host->username[sizeof(host->username) - 1] = '\0';
	std::printf("Username '%s' applied\n\n", host->username);
}

void CommandSetPassword(Target* host, const char* password) {
	std::strncpy(host->password, password, sizeof(host->password) - 1);
	host->password[sizeof(host->password) - 1] = '\0';
	std::printf("Password is applied\n\n");
}

void CommandStatus(const Target* host) {
	std::printf("Address: %s\n", host->address);
	std::printf("Username: %s\n", host->username);
	std::printf("Password: %s\n\n", host->password);
}

void CommandClearTarget(Target* host) {
	host->username[0] = '\0';
	host->password[0] = '\0';
	host->address[0] = '\0';
	host->state = DISCONNECTED;
	std::printf("Username, password and address cleared\n\n");

}

int check_ipv4(const char* data) {
	if (data == nullptr) {
		return 0;
	}

	int a = 0;
	int b = 0;
	int c = 0;
	int d = 0;
	char tail = '\0';

	const int parsed = sscanf_s(data, "%d.%d.%d.%d%c", &a, &b, &c, &d, &tail, 1);

	if (parsed != 4) {
		return 0;
	}

	if (a < 0 || a > 255) return 0;
	if (b < 0 || b > 255) return 0;
	if (c < 0 || c > 255) return 0;
	if (d < 0 || d > 255) return 0;

	return 1;
}

int check_port(const char* data) {
	int a = 0;
	const int parsed = sscanf_s(data, "%d", &a);
	if (parsed != 1) return 0;
	if (a < 0 || a > 65535) return 0;

	return 1;
}
