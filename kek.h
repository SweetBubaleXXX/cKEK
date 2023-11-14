#pragma once

#include "base.h"

#define CHECK_BASE_CLASS static_assert(\
    std::is_base_of<Base::SymmetricKey, TSymmetricKey>::value,\
    "TSymmeticKey must derive from Base::SymmetricKey"\
    );

namespace Kek
{
    template <class TSymmetricKey>
    class PublicKey : virtual public Base::PublicKey
    {
        CHECK_BASE_CLASS;
    public:
        PublicKey(std::istream& serialized_key)
        {
            key = key_factory.load_public_key(serialized_key);
        }

        PublicKey(PrivateKey<TAsymmetricKeyFactory, TSymmetricKey>* private_key)
        {
            key = key_factory.create_public_key(private_key->key);
        }

        unsigned int get_key_size() const override
        {
            return key->get_key_size();
        }

        void serialize(std::ostream& output_stream) const override
        {
            key->serialize(output_stream);
        }

        void encrypt(std::ostream& output_stream, std::istream& input_stream) const override
        {
            
        }

        bool verify(std::istream& signature, std::istream& message) const override
        {
            return key->verify(signature, message);
        }
    private:
        TAsymmetricKeyFactory key_factory;
        std::unique_ptr<Base::PublicKey> key;
    };

    template <class TSymmetricKey>
    class PrivateKey : virtual public Base::PrivateKey
    {
        CHECK_BASE_CLASS;
    public:
        //template <class TSymmetricKey>
        //friend class PublicKey;

        PrivateKey(std::istream& serialized_key)
        {
            key = key_factory.load_private_key(serialized_key);
        }

        PrivateKey(std::istream& serialized_key, std::string& password)
        {
            key = key_factory.load_private_key(serialized_key, password);
        }

        static PrivateKey* generate(unsigned int key_size, const std::vector<uint8_t>* seed = nullptr)
        {
            TAsymmetricKeyFactory key_factory;
            Base::PrivateKey* private_key = key_factory.generate_private_key(key_size, seed);
            return new PrivateKey(private_key);
        }

        unsigned int get_key_size() const override
        {
            return key->get_key_size()
        }

        void serialize(std::ostream& output_stream) const override
        {
            return key->serialize(output_stream);
        }

        void serialize(std::ostream& output_stream, const std::string& password) const override
        {
            return key->serialize(output_stream, password);
        }

        Base::PublicKey* generate_public_key() const override
        {
            return new PublicKey<TAsymmetricKeyFactory, TSymmetricKey>(this);
        }

        void decrypt(std::ostream& output_stream, std::istream& input_stream) const override
        {

        }

        void sign(std::ostream& output_stream, std::istream& input_stream) const
        {
            key->sign(output_stream, input_stream);
        }
    private:
        std::unique_ptr<Base::AsymmetricKeyFactory> key_factory;
        std::unique_ptr<Base::PrivateKey> key;

        PrivateKey(Base::PrivateKey* private_key) : key(private_key) {}
    };

    template <class TAsymmetricKeyFactory, class TSymmetricKey>
    class KeyFactory : virtual public Base::AsymmetricKeyFactory
    {
        CHECK_BASE_CLASS;
    public:
        PrivateKey* load_private_key(std::istream& serialized_key) const override
        {
            return new PrivateKey<TAsymmetricKeyFactory, TSymmetricKey>(serialized_key);
        }

        PrivateKey* load_private_key(std::istream& serialized_key, std::string& password) const override
        {
            return new PrivateKey<TAsymmetricKeyFactory, TSymmetricKey>(serialized_key, password);
        }

        PrivateKey* generate_private_key(
            unsigned int key_size,
            const std::vector<uint8_t>* seed = nullptr
        ) const override
        {
            return PrivateKey<TAsymmetricKeyFactory, TSymmetricKey>::generate(key_size, seed);
        }

        PublicKey* load_public_key(std::istream& serialized_key) const override
        {
            return new PublicKey<TAsymmetricKeyFactory, TSymmetricKey>(serialized_key);
        }
    };
}
