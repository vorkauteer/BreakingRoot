#include "app.h"
#include "command.h"

#include <cstdio>
#include <cstring>

static void JoinArguments(int argc, char* argv[], char* output, std::size_t outputSize) {
    if (output == nullptr || outputSize == 0) return;

    output[0] = '\0';
    std::size_t used = 0;

    for (int i = 1; i < argc; ++i) {
        const char* part = argv[i] ? argv[i] : "";
        const std::size_t partLen = std::strlen(part);
        const std::size_t separatorLen = (i > 1) ? 1 : 0;

        if (used + separatorLen + partLen + 1 >= outputSize) {
            break;
        }

        if (separatorLen == 1) {
            output[used++] = ' ';
            output[used] = '\0';
        }

        std::memcpy(output + used, part, partLen);
        used += partLen;
        output[used] = '\0';
    }
}

int main(int argc, char* argv[]) {
    Target target{};
    CliState cli{};
    char input[MAX_INPUT]{};
    char prompt[MAX_PROMPT]{};

    InitApp(&target, &cli);
    PrintBanner();

    if (argc > 1) {
        JoinArguments(argc, argv, input, sizeof(input));
        if (input[0] != '\0') {
            ParseCommand(&target, &cli, input);
        }
        return 0;
    }

    while (true) {
        BuildPrompt(&cli, prompt, sizeof(prompt));

        if (!ReadCommandLine(prompt, input, sizeof(input))) {
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
