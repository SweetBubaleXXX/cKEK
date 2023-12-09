#pragma once

#include <conio.h>
#include <filters.h>
#include "base.h"
#include "rsa.h"
#include "aes.h"
#include "kek.h"
#include "context.h"

class CommandExecutor
{
public:
    CommandExecutor(AppContext& context) : context(context) {}

    void generate_key()
    {
        Kek::KeyFactory<Rsa::KeyFactory, Aes::CbcModeKeyFactory<256>> key_factory;
        auto seed = read_seed();
        auto private_key = std::unique_ptr<Base::PrivateKey>(
            key_factory.generate_private_key(context.key_size, seed.get())
        );
        std::string password;
        get_password(password);
        std::ofstream output_file(context.output_file, std::ios::out | std::ios::binary);
        if (password.empty())
            private_key->serialize(output_file);
        else
            private_key->serialize(output_file, password);
    }

    void export_public_key()
    {

    }

    void encrypt()
    {

    }

    void decrypt()
    {

    }

    void sign()
    {

    }

    void verify()
    {

    }
private:
    AppContext& context;

    void get_password(std::string& password) const
    {
        if (!context.password_file.empty())
        {
            std::ifstream password_file(context.password_file);
            std::stringstream buffer;
            buffer << password_file.rdbuf();
            password = buffer.str();
        }
        std::cout << "Enter password (leave empty for no password): ";
        char c;
        while ((c = _getch()) != '\r')
        {
            password.push_back(c);
            _putch('*');
        }
        std::cout << std::endl;
        return;
    }

    std::unique_ptr<std::vector<uint8_t>> read_seed()
    {
        if (context.seed_file.empty())
            return std::unique_ptr<std::vector<uint8_t>>(nullptr);
        auto seed = new std::vector<uint8_t>(Rsa::SEED_SIZE);
        CryptoPP::FileSource seed_source(context.seed_file.c_str(), true,
            new CryptoPP::HexDecoder(
                new CryptoPP::ArraySink(seed->data(), seed->size())
            )
        );
        return std::unique_ptr<std::vector<uint8_t>>(seed);
    }
};
