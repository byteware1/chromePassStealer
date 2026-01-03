#include <iostream>
#include <string>
#include "program.h"
#include <windows.h>

int main() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);

    std::cout << "        _                _      \n";
    std::cout << "       / \\   _ __  _ __ | | ___ \n";
    std::cout << "      / _ \\ | '_ \\| '_ \\| |/ _ \\ \n";
    std::cout << "     / ___ \\| |_) | |_) | |  __/\n";
    std::cout << "    /_/   \\_\\ .__/| .__/|_|\\___|\n";
    std::cout << "            |_|   |_|           \n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    std::cout << "\n     SKYPORTAL DISCORD MALWARE   \n";
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    std::string cmd;
    std::cout << "\n>> ";
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::cin >> cmd;

    if (cmd == "run") {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        std::string cmd_sure;
        std::cout << "\nAre you sure you want to start this procedure (it involves danger)? (Y/n): ";
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
        std::cin >> cmd_sure;
        if (cmd_sure == "Y" || cmd_sure == "y") {
            runSavedPasswords();
        }
        else {
            std::cout << "\nOperation cancelled by user.\n";
        }
    }
    return 0;
}
