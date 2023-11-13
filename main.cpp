#include <vector>
#include "rsa.h"

int main(int argc, char* argv[])
{
    std::unique_ptr<Rsa::PrivateKey> private_key(Rsa::PrivateKey::generate(2048));
    private_key->serialize(std::cout);
    return 0;
}
