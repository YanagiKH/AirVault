#include "airvault/core.hpp"
#include <iostream>
#include <string>

int main(const int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: airvault-core <sha256|check-path> <value>\n";
        return 2;
    }
    try {
        const std::string command(argv[1]);
        if (command == "sha256") {
            const auto digest = airvault::sha256_file(argv[2]);
            std::cout << airvault::hex_encode(digest) << '\n';
            return 0;
        }
        if (command == "check-path") {
            const bool safe = airvault::is_safe_relative_path(argv[2]);
            std::cout << (safe ? "safe" : "unsafe") << '\n';
            return safe ? 0 : 1;
        }
        std::cerr << "Unknown command\n";
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "AirVault core error: " << error.what() << '\n';
        return 1;
    }
}
