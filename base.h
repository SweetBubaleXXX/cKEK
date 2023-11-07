#pragma once

#include <iostream>
#include <vector>

namespace Base {
    class Key
    {
    protected:
        int key_size;
    public:
        virtual int get_key_size() = 0;
        virtual void serialize(std::ostream) = 0;
    };

    class PublicKey : virtual Key
    {
    public:
        virtual void encrypt(std::ostream, const std::istream) = 0;
        virtual void verify(std::ostream, const std::istream) = 0;
    };

    class PrivateKey : virtual Key
    {
    public:
        virtual PublicKey gen_public_key() = 0;
        virtual void decrypt(std::ostream, const std::istream) = 0;
        virtual void sign(std::ostream, const std::istream) = 0;
        virtual void serialize(std::ostream, const std::string password) = 0;
    };

    class SymmetricKey : virtual Key
    {
    public:
        virtual void encrypt(std::ostream, const std::istream, const std::vector<uint8_t> iv) = 0;
        virtual void decrypt(std::ostream, const std::istream, const std::vector<uint8_t> iv) = 0;
    };

    class AsymmetricKeyFactory
    {
    public:
        virtual PrivateKey create_private_key() = 0;
        virtual PublicKey create_public_key(PrivateKey) = 0;
    };
}
