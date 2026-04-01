#include "app.h"
#include "command.h"

#include <cstdio>
#include <cstring>

int main() {
    Target target{};
    CliState cli{};
    char input[MAX_INPUT]{};
    char prompt[MAX_PROMPT]{};

    InitApp(&target, &cli);
    PrintBanner();

    while (true) {
        BuildPrompt(&cli, prompt, sizeof(prompt));
        std::printf("%s", prompt);

        if (std::fgets(input, sizeof(input), stdin) == nullptr) {
            break;
        }

        input[std::strcspn(input, "\r\n")] = '\0';

        if (input[0] == '\0') {
            continue;
        }

        ParseCommand(&target, &cli, input);
    }

    return 0;
}