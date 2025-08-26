#pragma once

#include <filesystem>
#include "Key15.h"


class IDecryptor
{
    public:
      virtual ~IDecryptor() = default;

      [[nodiscard]] virtual bool canDecrypt(const std::filesystem::path& encryptedFile) const = 0;
      [[nodiscard]] virtual bool decrypt(const std::filesystem::path& encryptedFile,
                           const Key15& key, 
                           const std::filesystem::path& outputDir) const = 0;
};