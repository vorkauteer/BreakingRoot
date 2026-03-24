#include "app.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

void ParseCommand(Target* host, const char* input) {
    if (host == nullptr || input == nullptr) {
        return;
    }

    //if (app->state == CONNECTED) {
    //    //if (std::strncmp(input, "-", 1) == 0) {
    //    //    const char* moduleName = input + 1;
    //    //    const int rc = interpretator(moduleName);
    //    //    std::printf("Module exit code: %d\n\n", rc);
    //    //    return;
    //    //}
    //    if (std::strcmp(input, "disconnect") == 0) {
    //        disconnectFromTarget(host);
    //        return;
    //    }
    //    else if (std::strcmp(input, "status") == 0) {
    //        printStatus(host);
    //        return;
    //    }
    //    else if (std::strcmp(input, "help") == 0) {
    //        CommandHelp();
    //        return;
    //    }
    //    else if (std::strcmp(input, "exit") == 0) {
    //        disconnectFromTarget(host);
    //        std::printf("Exiting...\n\n");
    //        std::exit(0);
    //    }

    //    sendToPeer(host, input);
    //    return;
    //}
    //else if (host->state != CONNECTED && std::strncmp(input, "-", 1) == 0) {
    //    std::printf("First you need to establish a connection\n\n");
    //    return;
    //}

    if (std::strcmp(input, "help") == 0) {
        CommandHelp();
    }
    else if (std::strncmp(input, "target ", 7) == 0) {
        CommandSetTarget(host, input + 7);
    }
    else if (std::strncmp(input, "port ", 5) == 0) {
        CommandSetPort(host, input + 5);
    }
    else if (std::strncmp(input, "username ", 9) == 0) {
        CommandSetUsername(host, input + 9);
    }
    else if (std::strncmp(input, "password ", 9) == 0) {
        CommandSetPassword(host, input + 9);
    }
    else if (std::strcmp(input, "clear-target") == 0) {
        CommandClearTarget(host);
    }
    //else if (std::strcmp(input, "connect") == 0) {
    //    connectToTarget(host);
    //}
    //else if (std::strcmp(input, "disconnect") == 0) {
    //    disconnectFromTarget(host);
    //}
    else if (std::strcmp(input, "status") == 0) {
        CommandStatus(host);
    }
    else if (std::strcmp(input, "exit") == 0) {
        std::printf("Goodbye...\n");
        std::exit(0);
    }
    else {
        std::printf("Unknown command. Type 'help'.\n\n");
    }
}