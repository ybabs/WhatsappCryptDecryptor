#pragma once

#include "IDecryptor.h"
#include "Key15.h"

class Crypt15Decryptor : public IDecryptor
{
public:
    Crypt15Decryptor() = default;
    ~Crypt15Decryptor() override = default;

    [[nodiscard]] bool canDecrypt(const std::filesystem::path& encryptedFile) const override;
    [[nodiscard]] bool decrypt(const std::filesystem::path& encryptedFile,
                 const Key15& key, 
                 const std::filesystem::path& outputDir) const override;
};
