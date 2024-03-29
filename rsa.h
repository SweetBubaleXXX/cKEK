#pragma once

#include <pem.h>
#include <files.h>
#include <osrng.h>
#include <modes.h>
#include <aes.h>
#include <pssr.h>
#include "base.h"

namespace Rsa {
    const std::string KEY_ENCRYPTION_ALGORITHM = "AES-256-CBC";
    const unsigned int SEED_SIZE = CryptoPP::AES::BLOCKSIZE;

    class PublicKey : virtual public Base::PublicKey
    {
    public:
        friend class PrivateKey;

        PublicKey(std::istream& serialized_key)
        {
            CryptoPP::FileSource stream(serialized_key, true);
            CryptoPP::PEM_Load(stream, key);
        }

        unsigned int get_key_size() const override
        {
            return key.GetModulus().BitCount();
        }

        void serialize(std::ostream& output_stream) const override
        {
            CryptoPP::FileSink stream_sink(output_stream);
            CryptoPP::PEM_Save(stream_sink, key);
        }

        void encrypt(std::ostream& output_stream, std::istream& input_stream) const override
        {
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(key);
            CryptoPP::PK_EncryptorFilter encryption_filter(rng, encryptor,
                new CryptoPP::FileSink(output_stream)
            );
            CryptoPP::FileSource stream(input_stream, false);
            stream.Attach(new CryptoPP::Redirector(encryption_filter));
            stream.Pump(get_key_size() / 8);
            encryption_filter.MessageEnd();
        }

        bool verify(std::istream& signature, std::istream& message) const override
        {
            CryptoPP::byte result = 0;
            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Verifier verifier(key);
            CryptoPP::SignatureVerificationFilter verification_filter(verifier,
                new CryptoPP::ArraySink(&result, sizeof(result))
            );
            CryptoPP::FileSource signature_source(signature, true);
            CryptoPP::FileSource message_source(message, true);
            signature_source.TransferTo(verification_filter);
            message_source.TransferTo(verification_filter);
            verification_filter.MessageEnd();
            return !!result;
        }
    private:
        CryptoPP::RSA::PublicKey key;

        PublicKey(CryptoPP::RSA::PublicKey rsa_key) :
            key(rsa_key)
        {}
    };

    class PrivateKey : virtual public Base::PrivateKey
    {
    public:
        PrivateKey(std::istream& serialized_key)
        {
            CryptoPP::FileSource stream(serialized_key, true);
            CryptoPP::PEM_Load(stream, key);
        }

        PrivateKey(std::istream& serialized_key, std::string& password)
        {
            CryptoPP::FileSource stream(serialized_key, true);
            CryptoPP::PEM_Load(stream, key, password.c_str(), password.length());
        }

        static PrivateKey* generate(unsigned int key_size)
        {
            CryptoPP::AutoSeededRandomPool rng;
            return PrivateKey::generate(rng, key_size);
        }

        static PrivateKey* generate(unsigned int key_size, const std::vector<uint8_t>& seed)
        {
            if (seed.size() != SEED_SIZE)
                throw std::exception("Invalid seed size");
            CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption rng;
            rng.SetKeyWithIV(seed.data(), seed.size(), seed.data(), seed.size());
            return PrivateKey::generate(rng, key_size);
        }

        unsigned int get_key_size() const override
        {
            return key.GetModulus().BitCount();
        }

        void serialize(std::ostream& output_stream) const override
        {
            CryptoPP::FileSink stream_sink(output_stream);
            CryptoPP::PEM_Save(stream_sink, key);
        }

        void serialize(std::ostream& output_stream, const std::string& password) const override
        {
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::FileSink stream_sink(output_stream);
            CryptoPP::PEM_Save(stream_sink, key, rng, KEY_ENCRYPTION_ALGORITHM, password.c_str(), password.length());
        }

        PublicKey* get_public_key() const override
        {
            CryptoPP::RSA::PublicKey rsa_public_key(key);
            return new PublicKey(rsa_public_key);
        }

        void decrypt(std::ostream& output_stream, std::istream& input_stream) const override
        {
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(key);
            CryptoPP::PK_DecryptorFilter decrypiton_filter(rng, decryptor,
                new CryptoPP::FileSink(output_stream)
            );
            CryptoPP::FileSource stream(input_stream, false);
            stream.Attach(new CryptoPP::Redirector(decrypiton_filter));
            stream.Pump(get_key_size() / 8);
            decrypiton_filter.MessageEnd();
        }

        void sign(std::ostream& output_stream, std::istream& input_stream) const override
        {
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::RSASS<CryptoPP::PSS, CryptoPP::SHA256>::Signer signer(key);
            CryptoPP::FileSource stream(input_stream, true,
                new CryptoPP::SignerFilter(rng, signer,
                    new CryptoPP::FileSink(output_stream)
                )
            );
        }
    private:
        CryptoPP::RSA::PrivateKey key;

        PrivateKey(CryptoPP::RSA::PrivateKey rsa_key) : key(rsa_key) {}

        static PrivateKey* generate(CryptoPP::RandomNumberGenerator& rng, unsigned int key_size)
        {
            CryptoPP::RSA::PrivateKey rsa_key;
            rsa_key.GenerateRandomWithKeySize(rng, key_size);
            return new PrivateKey(rsa_key);
        }
    };

    class KeyFactory : virtual public Base::AsymmetricKeyFactory
    {
    public:
        PublicKey* load_public_key(std::istream& serialized_key) const override
        {
            return new PublicKey(serialized_key);
        }

        PrivateKey* load_private_key(std::istream& serialized_key) const override
        {
            return new PrivateKey(serialized_key);
        }

        PrivateKey* load_private_key(std::istream& serialized_key, std::string& password) const override
        {
            return new PrivateKey(serialized_key, password);
        }

        PrivateKey* generate_private_key(
            unsigned int key_size,
            const std::vector<uint8_t>* seed = nullptr
        ) const override
        {
            if (seed)
                return PrivateKey::generate(key_size, *seed);
            return PrivateKey::generate(key_size);
        }
    };
}
