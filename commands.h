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
        std::ofstream output_file(context.output_file);
        if (password.empty())
            private_key->serialize(output_file);
        else
            private_key->serialize(output_file, password);
    }

    void export_public_key()
    {
        Kek::KeyFactory<Rsa::KeyFactory, Aes::CbcModeKeyFactory<256>> key_factory;
        std::string password;
        get_password(password);
        std::ifstream key_file(context.key_file, std::ios::binary);
        std::unique_ptr<Base::PrivateKey> private_key;
        if (password.empty())
            private_key = std::unique_ptr<Base::PrivateKey>(key_factory.load_private_key(key_file));
        else
            private_key = std::unique_ptr<Base::PrivateKey>(key_factory.load_private_key(key_file, password));
        auto public_key = std::unique_ptr<Base::PublicKey>(private_key->get_public_key());
        std::ofstream output_file(context.output_file);
        public_key->serialize(output_file);
    }

    void encrypt()
    {
        Kek::KeyFactory<Rsa::KeyFactory, Aes::CbcModeKeyFactory<256>> key_factory;
        std::ifstream key_file(context.key_file, std::ios::binary);
        auto public_key = std::unique_ptr<Base::PublicKey>(key_factory.load_public_key(key_file));
        std::ifstream input_file(context.input_file, std::ios::binary);
        std::ofstream output_file(context.output_file, std::ios::binary);
        public_key->encrypt(output_file, input_file);
    }

    void decrypt()
    {
        Kek::KeyFactory<Rsa::KeyFactory, Aes::CbcModeKeyFactory<256>> key_factory;
        std::string password;
        get_password(password);
        std::ifstream key_file(context.key_file, std::ios::binary);
        std::unique_ptr<Base::PrivateKey> private_key;
        if (password.empty())
            private_key = std::unique_ptr<Base::PrivateKey>(key_factory.load_private_key(key_file));
        else
            private_key = std::unique_ptr<Base::PrivateKey>(key_factory.load_private_key(key_file, password));
        std::ifstream input_file(context.input_file, std::ios::binary);
        std::ofstream output_file(context.output_file, std::ios::binary);
        private_key->decrypt(output_file, input_file);
    }

    void sign()
    {
        Kek::KeyFactory<Rsa::KeyFactory, Aes::CbcModeKeyFactory<256>> key_factory;
        std::string password;
        get_password(password);
        std::ifstream key_file(context.key_file, std::ios::binary);
        std::unique_ptr<Base::PrivateKey> private_key;
        if (password.empty())
            private_key = std::unique_ptr<Base::PrivateKey>(key_factory.load_private_key(key_file));
        else
            private_key = std::unique_ptr<Base::PrivateKey>(key_factory.load_private_key(key_file, password));
        std::ifstream input_file(context.input_file, std::ios::binary);
        std::ofstream output_file(context.output_file, std::ios::binary);
        private_key->sign(output_file, input_file);
    }

    void verify()
    {
        Kek::KeyFactory<Rsa::KeyFactory, Aes::CbcModeKeyFactory<256>> key_factory;
        std::ifstream key_file(context.key_file, std::ios::binary);
        auto public_key = std::unique_ptr<Base::PublicKey>(key_factory.load_public_key(key_file));
        std::ifstream signature_file(context.signature_file, std::ios::binary);
        std::ifstream input_file(context.input_file, std::ios::binary);
        bool is_valid = public_key->verify(signature_file, input_file);
        if (is_valid)
            std::cout << "Signature is valid" << std::endl;
        else
            throw std::exception("Signature is invalid");
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
