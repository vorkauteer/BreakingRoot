#include "app.h"

int main()
{
	Target host{};
	char input[MAX_INPUT]{};
	char prompt[256]{};

	InitApp(&host);

	std::printf("ITSecurity community project\n");
	std::printf("Type \'help\' to see all commands\n\n");

	while (&host) {
		CommandLine(&host, prompt, sizeof(prompt));
		std::printf("%s", prompt);

		if (std::fgets(input, sizeof(input), stdin) == nullptr) {
			break;
		}

		input[std::strcspn(input, "\r\n")] = '\0';
		
		if (input[0] == '\0') {
			continue;
		}

		ParseCommand(&host, input);

	}

	return 0;
}