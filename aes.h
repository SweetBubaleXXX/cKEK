#pragma once

#include <files.h>
#include <osrng.h>
#include <modes.h>
#include <aes.h>
#include <hex.h>
#include "base.h"

namespace Aes
{
    const unsigned int DEFAULT_KEY_SIZE = CryptoPP::AES::DEFAULT_KEYLENGTH * 8;
    const unsigned int IV_SIZE = CryptoPP::AES::BLOCKSIZE * 8;

    class CbcModeKey : public Base::SymmetricKey
    {
    public:
        CbcModeKey(const std::vector<uint8_t>& key)
        {
            CryptoPP::SecByteBlock key_block(reinterpret_cast<const CryptoPP::byte*>(key.data()), key.size());
            this->key = key_block;
        }

        static CbcModeKey* generate(unsigned int key_size = DEFAULT_KEY_SIZE)
        {
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::SecByteBlock key(key_size / 8);
            rng.GenerateBlock(key, key.size());
            return new CbcModeKey(key);
        }

        unsigned int get_key_size() const override
        {
            return static_cast<unsigned int>(key.size() * 8);
        }

        unsigned int get_iv_size() const override
        {
            return IV_SIZE;
        }

        void serialize(std::ostream& output_stream) const override
        {
            output_stream.write(reinterpret_cast<const char*>(key.data()), key.size());
        }

        void encrypt(
            std::ostream& output_stream,
            std::istream& input_stream,
            const std::vector<uint8_t>* iv = nullptr
        ) const override
        {
            process_stream<CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption>(output_stream, input_stream, iv);
        }

        void decrypt(
            std::ostream& output_stream,
            std::istream& input_stream,
            const std::vector<uint8_t>* iv = nullptr
        ) const override
        {
            process_stream<CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption>(output_stream, input_stream, iv);
        }
    private:
        CryptoPP::SecByteBlock key;

        CbcModeKey(CryptoPP::SecByteBlock key_block) :
            key(key_block)
        {}

        template <class TProcessor>
        void process_stream(
            std::ostream& output_stream,
            std::istream& input_stream,
            const std::vector<uint8_t>* iv
        ) const
        {
            static_assert(
                std::is_base_of<CryptoPP::CBC_ModeBase, TProcessor>::value,
                "TProcessor must derive from CryptoPP::CBC_ModeBase"
                );
            TProcessor processor;
            set_iv(processor, iv);
            CryptoPP::FileSource stream(input_stream, true,
                new CryptoPP::StreamTransformationFilter(processor,
                    new CryptoPP::FileSink(output_stream)
                )
            );
        }

        void set_iv(CryptoPP::CBC_ModeBase& encryptor, const std::vector<uint8_t>* iv) const
        {
            if (iv)
                encryptor.SetKeyWithIV(key, key.size(), iv->data(), iv->size());
            else
                encryptor.SetKey(key, key.size());
        }
    };

    template <unsigned int key_size = DEFAULT_KEY_SIZE>
    class CbcModeKeyFactory : virtual public Base::SymmetricKeyFactory
    {
    public:
        CbcModeKey* load(std::istream& input_stream) const override
        {
            CryptoPP::SecByteBlock key_block(key_size / 8);
            input_stream.read(reinterpret_cast<char*>(key_block.data()), key_block.size());
            if (input_stream.gcount() != key_block.size())
                throw std::exception();
            std::vector<uint8_t> key(key_block.begin(), key_block.end());
            return new CbcModeKey(key);
        }

        CbcModeKey* generate() const override
        {
            return CbcModeKey::generate(key_size);
        }
    };
};
