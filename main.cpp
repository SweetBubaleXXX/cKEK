#include <iostream>
#include <iomanip>
#include <vector>
#include <filters.h>
#include "aes.h"
#include "base.h"
#include "rsa.h"
#include "kek.h"

int main(int argc, char* argv[])
{
    std::unique_ptr<Rsa::PrivateKey> private_key(Rsa::PrivateKey::generate(2048));
    private_key->serialize(std::cout);
    std::unique_ptr<Base::PublicKey> public_key(private_key->get_public_key());
    public_key->serialize(std::cout);
    std::string message("Message text");
    std::stringstream content(message);
    std::stringstream encrypted_message;
    public_key->encrypt(encrypted_message, content);
    private_key->decrypt(std::cout, encrypted_message);

    Rsa::KeyFactory factory;
    Rsa::PrivateKey* new_key = factory.generate_private_key(2048);
    std::cout << new_key->get_key_size() << std::endl;
    delete new_key;

    std::stringstream plain_text(message);
    std::stringstream cipher;

    std::unique_ptr<Aes::CbcModeKey> key(Aes::CbcModeKey::generate());
    std::cout << key->get_key_size() << std::endl;
    std::vector<uint8_t> iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    key->encrypt(cipher, plain_text, &iv);
    key->decrypt(std::cout, cipher, &iv);

    Kek::KeyFactory<Rsa::KeyFactory, Aes::CbcModeKeyFactory<>> kek_factory;
    std::unique_ptr<Base::PrivateKey> kek_key(kek_factory.generate_private_key(1024));
    kek_key->serialize(std::cout, message);
    Kek::PrivateKey<Rsa::KeyFactory, Aes::CbcModeKeyFactory<>>* kek_private = kek_factory.generate_private_key(1024);
    Kek::PublicKey<Rsa::KeyFactory, Aes::CbcModeKeyFactory<>>* kek_public = kek_private->get_public_key();
    kek_public->serialize(std::cout);
    std::stringstream key_id;
    std::cout << kek_private->get_key_id() << std::endl;
    std::string hex_id = kek_public->get_key_id();
    std::cout << hex_id << std::endl;
    std::stringstream text(std::string("Simple message"));
    std::stringstream output;
    kek_public->encrypt(output, text);
    for (char byte : output.str())
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(byte));
    }
    return 0;
}
