#pragma once

#include <string>

struct AppContext
{
    int key_size = 2048;
    std::string key_file;
    std::string output_file;
    std::string input_file;
    std::string signature_file;
    std::string seed_file;
    std::string password_file;
};
