#include <iostream>
#include "CLI11.hpp"
#include "context.h"
#include "commands.h"

int main(int argc, char* argv[])
{
    AppContext context;
    CommandExecutor executor(&context);

    CLI::App app("KEK");
    app.require_subcommand(1);

    auto generate_sub_app = app.add_subcommand("generate", "generate private key");
    generate_sub_app->add_option("OUTPUT_FILE", context.output_file)->required();
    generate_sub_app->add_option("-s,--size", context.key_size);
    generate_sub_app->add_option("--seed", context.seed_file, "file with seed")->check(CLI::ExistingFile);
    generate_sub_app->add_option("-p,--password-file", context.password_file)->check(CLI::ExistingFile);
    generate_sub_app->callback(std::bind(&CommandExecutor::generate_key, &executor));

    auto export_public_key_sub_app = app.add_subcommand("export-public-key");
    export_public_key_sub_app->add_option("OUTPUT_FILE", context.output_file)->required();
    export_public_key_sub_app->add_option("-k,--key", context.key_file, "file with private key")
        ->check(CLI::ExistingFile)->required();
    export_public_key_sub_app->add_option("-p,--password-file", context.password_file)->check(CLI::ExistingFile);
    export_public_key_sub_app->callback(std::bind(&CommandExecutor::export_public_key, &executor));

    auto encrypt_sub_app = app.add_subcommand("encrypt", "encrypt file");
    encrypt_sub_app->add_option("INPUT_FILE", context.input_file)->check(CLI::ExistingFile)->required();
    encrypt_sub_app->add_option("OUTPUT_FILE", context.output_file)->required();
    encrypt_sub_app->add_option("-k,--key", context.key_file, "file with public key")
        ->check(CLI::ExistingFile)->required();
    encrypt_sub_app->callback(std::bind(&CommandExecutor::encrypt, &executor));

    auto decrypt_sub_app = app.add_subcommand("decrypt", "decrypt file");
    decrypt_sub_app->add_option("INPUT_FILE", context.input_file)->check(CLI::ExistingFile)->required();
    decrypt_sub_app->add_option("OUTPUT_FILE", context.output_file)->required();
    decrypt_sub_app->add_option("-k,--key", context.key_file, "file with private key")
        ->check(CLI::ExistingFile)->required();
    decrypt_sub_app->add_option("-p,--password-file", context.password_file)->check(CLI::ExistingFile);
    decrypt_sub_app->callback(std::bind(&CommandExecutor::decrypt, &executor));

    auto sign_sub_app = app.add_subcommand("sign", "create signature");
    sign_sub_app->add_option("INPUT_FILE", context.input_file)->check(CLI::ExistingFile)->required();
    sign_sub_app->add_option("OUTPUT_FILE", context.output_file)->required();
    sign_sub_app->add_option("-k,--key", context.key_file, "file with private key")
        ->check(CLI::ExistingFile)->required();
    sign_sub_app->add_option("-p,--password-file", context.password_file)->check(CLI::ExistingFile);
    sign_sub_app->callback(std::bind(&CommandExecutor::sign, &executor));

    auto verify_sub_app = app.add_subcommand("verify", "verify signature");
    verify_sub_app->add_option("INPUT_FILE", context.input_file)->check(CLI::ExistingFile)->required();
    verify_sub_app->add_option("SIGNATURE_FILE", context.signature_file)->check(CLI::ExistingFile)->required();
    verify_sub_app->add_option("-k,--key", context.key_file, "file with public key")
        ->check(CLI::ExistingFile)->required();
    verify_sub_app->callback(std::bind(&CommandExecutor::verify, &executor));

    try
    {
        CLI11_PARSE(app, argc, argv);
    }
    catch (std::exception& exc)
    {
        std::cerr << exc.what() << std::endl;
    }

    return 0;
}
