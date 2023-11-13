#include <files.h>
#include <osrng.h>
#include <modes.h>
#include <aes.h>
#include "base.h"

namespace Aes
{
    const unsigned int DEFAULT_KEY_SIZE = CryptoPP::AES::DEFAULT_KEYLENGTH * 8;

    class CbcModeKey : public Base::SymmetricKey
    {
    public:
        static CbcModeKey* generate(unsigned int key_size = DEFAULT_KEY_SIZE)
        {
            CryptoPP::AutoSeededRandomPool rng;
            CryptoPP::SecByteBlock key(key_size / 8);
            rng.GenerateBlock(key, key.size());
            return new CbcModeKey(key);
        }

        unsigned int get_key_size() const
        {
            return static_cast<unsigned int>(key.size() * 8);
        }

        void serialize(std::ostream& output_stream) const
        {
            output_stream << key;
        }

        void encrypt(
            std::ostream& output_stream,
            std::istream& input_stream,
            const std::vector<uint8_t>* iv = nullptr
        ) const
        {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
            set_iv(&encryptor, iv);
            CryptoPP::FileSource stream(input_stream, true,
                new CryptoPP::StreamTransformationFilter(encryptor,
                    new CryptoPP::FileSink(output_stream)
                )
            );
        }

        void decrypt(
            std::ostream& output_stream,
            std::istream& input_stream,
            const std::vector<uint8_t>* iv = nullptr
        ) const
        {
            CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryptor;
            set_iv(&decryptor, iv);
            CryptoPP::FileSource stream(input_stream, true,
                new CryptoPP::StreamTransformationFilter(decryptor,
                    new CryptoPP::FileSink(output_stream)
                )
            );
        }

    private:
        CryptoPP::SecByteBlock key;

        CbcModeKey(CryptoPP::SecByteBlock key_block) : key(key_block) {}

        void set_iv(CryptoPP::CBC_ModeBase* encryptor, const std::vector<uint8_t>* iv) const
        {
            if (iv)
                encryptor->SetKeyWithIV(key, key.size(), iv->data(), iv->size());
            else
                encryptor->SetKey(key, key.size());
        }
    };
}
