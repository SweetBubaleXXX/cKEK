#pragma once

#include <iostream>
#include <vector>

namespace Base {
    class Key
    {
    public:
        virtual unsigned int get_key_size() const = 0;
        virtual void serialize(std::ostream&) const = 0;
    };

    class PublicKey : virtual public Key
    {
    public:
        virtual void encrypt(std::ostream&, std::istream&) const = 0;
        virtual bool verify(std::istream& signature, std::istream& message) const = 0;
    };

    class PrivateKey : virtual public Key
    {
    public:
        virtual std::unique_ptr<PublicKey> generate_public_key() const = 0;
        virtual void decrypt(std::ostream&, std::istream&) const = 0;
        virtual void sign(std::ostream&, std::istream&) const = 0;
        virtual void serialize(std::ostream&, const std::string& password) const = 0;
    };

    class SymmetricKey : virtual public Key
    {
    public:
        virtual void encrypt(std::ostream&, std::istream&, const std::vector<uint8_t>* iv = nullptr) const = 0;
        virtual void decrypt(std::ostream&, std::istream&, const std::vector<uint8_t>* iv = nullptr) const = 0;
    };

    class AsymmetricKeyFactory
    {
    public:
        virtual std::unique_ptr<PrivateKey> load_private_key(std::istream&) const = 0;
        virtual std::unique_ptr<PrivateKey> load_private_key(std::istream&, std::string& password) const = 0;

        virtual std::unique_ptr<PrivateKey> generate_private_key(
            unsigned int key_size,
            const std::vector<uint8_t>* seed = nullptr
        ) const = 0;

        virtual std::unique_ptr<PublicKey> load_public_key(std::istream&) const = 0;
        virtual std::unique_ptr<PublicKey> create_public_key(const PrivateKey* private_key) const
        {
            return private_key->generate_public_key();
        };
    };
}
