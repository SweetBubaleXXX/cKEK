#pragma once

#include <array>
#include "base.h"

#define CHECK_TEMPLATE_CLASSES static_assert(\
    std::is_base_of<Base::AsymmetricKeyFactory, TAsymmetricKeyFactory>::value,\
    "TAsymmetricKeyFactory must derive from Base::AsymmetricKeyFactory"\
    );\
    static_assert(\
    std::is_base_of<Base::SymmetricKeyFactory, TSymmetricKeyFactory>::value,\
    "TSymmetricKeyFactory must derive from Base::SymmetricKeyFactory"\
    );

namespace Kek
{
    const uint8_t ALGORITHM_VERSION = 1;
    const size_t KEY_ID_LENGTH = 8;

    template <class TAsymmetricKeyFactory, class TSymmetricKeyFactory>
    class PublicKey : virtual public Base::PublicKey
    {
        CHECK_TEMPLATE_CLASSES;
    public:
        template <class TAsymmetricKeyFactory, class TSymmetricKey>
        friend class PrivateKey;

        PublicKey(std::istream& serialized_key) :
            key(asymmetric_key_factory.load_public_key(serialized_key))
        {}

        unsigned int get_key_size() const override
        {
            return key->get_key_size();
        }

        void get_key_id(std::ostream& output_stream) const
        {
            char buffer[KEY_ID_LENGTH];
            compute_key_id(buffer, KEY_ID_LENGTH);
            output_stream.write(buffer, KEY_ID_LENGTH);
        }

        std::string get_key_id() const
        {
            std::string hexadecimal_key_id;
            char buffer[KEY_ID_LENGTH];
            compute_key_id(buffer, KEY_ID_LENGTH);
            CryptoPP::ArraySource key_id_source(reinterpret_cast<uint8_t*>(buffer), KEY_ID_LENGTH, true,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(hexadecimal_key_id)
                )
            );
            return hexadecimal_key_id;
        }

        void serialize(std::ostream& output_stream) const override
        {
            key->serialize(output_stream);
        }

        void encrypt(std::ostream& output_stream, std::istream& input_stream) const override
        {
            output_stream.write(reinterpret_cast<const char*>(&ALGORITHM_VERSION), sizeof(ALGORITHM_VERSION));
            get_key_id(output_stream);
            std::unique_ptr<Base::SymmetricKey> symmetric_key(symmetric_key_factory.generate());
            auto iv = generate_iv(symmetric_key->get_iv_size() / 8);
            std::stringstream metadata;
            write_metadata(metadata, symmetric_key.get(), *iv);
            key->encrypt(output_stream, metadata);
            symmetric_key->encrypt(output_stream, input_stream, iv.get());
        }

        bool verify(std::istream& signature, std::istream& message) const override
        {
            return key->verify(signature, message);
        }
    private:
        TAsymmetricKeyFactory asymmetric_key_factory;
        TSymmetricKeyFactory symmetric_key_factory;
        std::unique_ptr<Base::PublicKey> key;

        PublicKey(const std::unique_ptr<Base::PrivateKey>& private_key) :
            key(private_key->get_public_key())
        {}

        void compute_key_id(char* buffer, size_t buffer_size) const
        {
            std::stringstream serialized_key;
            serialize(serialized_key);
            std::stringstream digest;
            CryptoPP::SHA256 hash;
            CryptoPP::FileSource hash_source(serialized_key, true,
                new CryptoPP::HashFilter(hash,
                    new CryptoPP::FileSink(digest)
                )
            );
            digest.read(buffer, buffer_size);
        }

        std::unique_ptr<std::vector<uint8_t>> generate_iv(unsigned int size) const
        {
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::SecByteBlock iv_block(size);
            rng.GenerateBlock(iv_block, iv_block.size());
            std::vector<uint8_t>* iv = new std::vector<uint8_t>(iv_block.begin(), iv_block.end());
            return std::make_unique<std::vector<uint8_t>>(*iv);
        }

        void write_metadata(
            std::ostream& metadata,
            const Base::SymmetricKey* key,
            const std::vector<std::uint8_t>& iv
        ) const
        {
            key->serialize(metadata);
            metadata.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        }
    };

    template <class TAsymmetricKeyFactory, class TSymmetricKeyFactory>
    class PrivateKey : virtual public Base::PrivateKey
    {
        CHECK_TEMPLATE_CLASSES;
    public:
        PrivateKey(std::istream& serialized_key) :
            key(asymmetric_key_factory.load_private_key(serialized_key))
        {}

        PrivateKey(std::istream& serialized_key, std::string& password) :
            key(asymmetric_key_factory.load_private_key(serialized_key, password))
        {}

        static PrivateKey* generate(unsigned int key_size, const std::vector<uint8_t>* seed = nullptr)
        {
            TAsymmetricKeyFactory key_factory;
            auto private_key = key_factory.generate_private_key(key_size, seed);
            return new PrivateKey(private_key);
        }

        unsigned int get_key_size() const override
        {
            return key->get_key_size();
        }

        void get_key_id(std::ostream& output_stream) const
        {
            std::unique_ptr<PublicKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>> public_key(get_public_key());
            public_key->get_key_id(output_stream);
        }

        std::string get_key_id() const
        {
            std::unique_ptr<PublicKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>> public_key(get_public_key());
            return public_key->get_key_id();
        }

        void serialize(std::ostream& output_stream) const override
        {
            key->serialize(output_stream);
        }

        void serialize(std::ostream& output_stream, const std::string& password) const override
        {
            key->serialize(output_stream, password);
        }

        PublicKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>* get_public_key() const override
        {
            return new PublicKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>(key);
        }

        void decrypt(std::ostream& output_stream, std::istream& input_stream) const override
        {
            parse_algorithm_version(input_stream);
            parse_key_id(input_stream);
            std::stringstream metadata;
            key->decrypt(metadata, input_stream);
            std::unique_ptr<Base::SymmetricKey> symmetric_key(symmetric_key_factory.load(metadata));
            auto iv = parse_iv(metadata, symmetric_key->get_iv_size() / 8);
            symmetric_key->decrypt(output_stream, input_stream, iv.get());
        }

        void sign(std::ostream& output_stream, std::istream& input_stream) const
        {
            key->sign(output_stream, input_stream);
        }
    private:
        TAsymmetricKeyFactory asymmetric_key_factory;
        TSymmetricKeyFactory symmetric_key_factory;
        std::unique_ptr<Base::PrivateKey> key;

        PrivateKey(Base::PrivateKey* private_key) : key(private_key) {}

        void parse_algorithm_version(std::istream& input_stream) const
        {
            uint8_t algorithm_version;
            input_stream.read(reinterpret_cast<char*>(&algorithm_version), sizeof(ALGORITHM_VERSION));
            if (algorithm_version != ALGORITHM_VERSION)
                throw std::exception("Incompatible algorithm version");
        }

        void parse_key_id(std::istream& input_stream) const
        {
            std::array<uint8_t, KEY_ID_LENGTH> encryption_key_id, current_key_id;
            input_stream.read(reinterpret_cast<char*>(encryption_key_id.data()), encryption_key_id.size());
            std::stringstream serialized_key_id;
            get_key_id(serialized_key_id);
            serialized_key_id.read(reinterpret_cast<char*>(current_key_id.data()), current_key_id.size());
            if (encryption_key_id != current_key_id)
                throw std::exception("Data was encrypted with key that has different id");
        }

        std::unique_ptr<std::vector<uint8_t>> parse_iv(std::istream& metadata, unsigned int iv_size) const
        {
            CryptoPP::SecByteBlock iv_block(iv_size);
            metadata.read(reinterpret_cast<char*>(iv_block.data()), iv_block.size());
            if (metadata.gcount() != iv_block.size())
                throw std::exception();
            auto iv = new std::vector<uint8_t>(iv_block.begin(), iv_block.end());
            return std::make_unique<std::vector<uint8_t>>(*iv);
        }
    };

    template <class TAsymmetricKeyFactory, class TSymmetricKeyFactory>
    class KeyFactory : virtual public Base::AsymmetricKeyFactory
    {
        CHECK_TEMPLATE_CLASSES;
    public:
        PublicKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>* load_public_key(
            std::istream& serialized_key
        ) const override
        {
            return new PublicKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>(serialized_key);
        }

        PrivateKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>* load_private_key(
            std::istream& serialized_key
        ) const override
        {
            return new PrivateKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>(serialized_key);
        }

        PrivateKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>* load_private_key(
            std::istream& serialized_key,
            std::string& password
        ) const override
        {
            return new PrivateKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>(serialized_key, password);
        }

        PrivateKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>* generate_private_key(
            unsigned int key_size,
            const std::vector<uint8_t>* seed = nullptr
        ) const override
        {
            return PrivateKey<TAsymmetricKeyFactory, TSymmetricKeyFactory>::generate(key_size, seed);
        }
    };
}
