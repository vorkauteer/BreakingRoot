
#pragma once

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <cstring>
#include <cstdio>

constexpr auto VERSION = "1.0-test";
constexpr auto MAX_INPUT = 1024;
constexpr auto MAX_TARGET = 128;
constexpr auto DEFAULT_PORT = 5985;
constexpr auto MAX_USERNAME = 128;
constexpr auto MAX_PASSWORD = 128;

enum SessionState {
	DISCONNECTED = 0,
	CONNECTED = 1
};

struct Target {
	char address[128];
	int port;
	int state;

	char username[128];
	char password[128];
};
