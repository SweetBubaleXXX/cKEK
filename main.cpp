#include <iostream>
#include <vector>
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
    key->serialize(std::cout);

    Kek::KeyFactory<Rsa::KeyFactory, Aes::CbcModeKey> kek_factory;
    std::unique_ptr<Base::PrivateKey> kek_key(kek_factory.generate_private_key(1024));
    kek_key->serialize(std::cout, message);
    kek_key->get_public_key()->serialize(std::cout);

    return 0;
}
