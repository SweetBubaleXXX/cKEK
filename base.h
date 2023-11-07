#pragma once

#include <iostream>

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
        virtual void encrypt(const std::istream, std::ostream) = 0;
        virtual void verify(const std::istream, std::ostream) = 0;
    };

    class PrivateKey : virtual Key
    {
    public:
        virtual PublicKey gen_public_key() = 0;
        virtual void decrypt(const std::istream, std::ostream) = 0;
        virtual void sign(const std::istream, std::ostream) = 0;
        virtual void serialize(const std::string password, std::ostream) = 0;
    };
}
