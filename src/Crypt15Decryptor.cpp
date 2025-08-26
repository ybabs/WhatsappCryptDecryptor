#include "Crypt15Decryptor.h"
#include "utils.h"
#include "Key15.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <filesystem>

// Generated from proto/
#include "backupPrefix.pb.h"
#include "logging.h"

bool Crypt15Decryptor::canDecrypt(const std::filesystem::path& p) const
{
    return p.extension() == ".crypt15";
}

bool Crypt15Decryptor::decrypt(const std::filesystem::path& encryptedFile,
                               const Key15& key,
                               const std::filesystem::path& outputDir) const
{
    auto md5Concat = [](const std::vector<std::vector<unsigned char>>& parts) -> std::optional<std::array<unsigned char,16>>
    {
        std::array<unsigned char,16> out{};
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx)
        {
            LOG_ERROR << "EVP_MD_CTX_new failed";
            return std::nullopt;
        }
        if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1)
        {
            EVP_MD_CTX_free(ctx);
            LOG_ERROR << "EVP_DigestInit_ex failed";
            return std::nullopt;
        }
        for (const auto& p : parts)
        {
            if (!p.empty() && EVP_DigestUpdate(ctx, p.data(), p.size()) != 1)
            {
                EVP_MD_CTX_free(ctx);
                LOG_ERROR << "EVP_DigestUpdate failed";
                return std::nullopt;
            }
        }
        unsigned int len=0;
        if (EVP_DigestFinal_ex(ctx, out.data(), &len) != 1 || len != out.size())
        {
            EVP_MD_CTX_free(ctx);
            LOG_ERROR << "EVP_DigestFinal_ex failed";
            return std::nullopt;
        }
        EVP_MD_CTX_free(ctx);
        return out;
    };

    auto gcmDecrypt = [&](const std::vector<unsigned char>& ciphertextPlusTag,
                           const std::vector<unsigned char>& keyBytes,
                           const std::vector<unsigned char>& iv) -> std::vector<unsigned char>
    {
        // decryptorUtils::aesGcmDecrypt expects ciphertext||tag (tag len = 16 by default)
        return decryptorUtils::aesGcmDecrypt(ciphertextPlusTag, keyBytes, iv);
    };

    try {
        if (!std::filesystem::exists(encryptedFile))
        {
            LOG_ERROR << "File does not exist: " + encryptedFile.string();
            return false;
        }

        // Read whole file
        const auto fileBytes = decryptorUtils::readBinaryFileSecure(encryptedFile);
        if (fileBytes.size() < 64)
        {
            LOG_ERROR << "File too small";
            return false;
        }
        size_t pos = 0;

        // 1) Header: [len][optional 0x01][BackupPrefix(len)]
        if (pos >= fileBytes.size())
        {
            LOG_ERROR << "Truncated Before Length";
            return false;
        }

        const uint8_t protobufLen = fileBytes[pos++];
        if (pos >= fileBytes.size())
        {
            LOG_ERROR << "Truncated after length";
            return false;
        }
        bool hasFeatureFlag = false;
        if (fileBytes[pos] == 0x01)
        {
            hasFeatureFlag = true;
            ++pos;
        }

        if (pos + protobufLen > fileBytes.size())
        {
            LOG_ERROR << "Truncated protobuf header";
            return false;
        }

        // Save the exact header bytes for MD5 computation
        std::vector<unsigned char> md5PartLen{ protobufLen };
        std::vector<unsigned char> md5PartFlag;
        if (hasFeatureFlag)
        {
            md5PartFlag = { 0x01 };
        }
        std::vector<unsigned char> md5PartPrefix(fileBytes.begin() + pos,fileBytes.begin() + pos + protobufLen);

        // Parse BackupPrefix
        BackupPrefix prefix;
        if (!prefix.ParseFromArray(fileBytes.data() + pos, static_cast<int>(protobufLen)))
        {
            LOG_ERROR << "Failed to parse BackupPrefix";
            return false;
        }
        pos += protobufLen;

        // Check crypt15 and extract IV
        if (prefix.cipher_info_case() != BackupPrefix::kC15Iv)
        {
            LOG_ERROR << "Not a crypt15 database (no c15_iv in header)";
            return false;
        }
        const std::string& ivString = prefix.c15_iv().iv();
        if (ivString.size() != 16)
        {
            LOG_ERROR << "IV must be 16 bytes, got " + std::to_string(ivString.size());
            return false;
        }
        std::vector<unsigned char> iv(ivString.begin(), ivString.end());

        // 2) Split: ciphertext | tag(16) | checksum(16)
        if (pos + 32 > fileBytes.size())
        {
            LOG_ERROR << "File missing tag/checksum";
            return false;
        }
        std::vector<unsigned char> remainder(fileBytes.begin() + pos, fileBytes.end());
        if (remainder.size() < 32)
        {
            LOG_ERROR << "Remainder too small";
            return false;
        }

        const size_t n = remainder.size();
        std::vector<unsigned char> checksum(remainder.begin() + (n - 16), remainder.end());
        std::vector<unsigned char> auth_tag(remainder.begin() + (n - 32), remainder.begin() + (n - 16));
        std::vector<unsigned char> enc(remainder.begin(), remainder.begin() + (n - 32));

        // 3) MD5(header parts + enc + auth_tag)
        const auto md5 = md5Concat({ md5PartLen, md5PartFlag, md5PartPrefix, enc, auth_tag });
        if (!md5)
        {
            LOG_ERROR << "Failed to retrieve md5, array empty";
            return false;
        }

        const bool checksum_ok = std::equal(checksum.begin(), checksum.end(), md5.value().begin());

        // 4) Derive AES-256-GCM key from Key15::get()
        const auto derived = key.get(); // HMAC loop("backup encryption")
        std::vector<unsigned char> aesKey(derived.begin(), derived.end());

        // Build ciphertext||tag for our decrypt helper.
        std::vector<unsigned char> ctWithTag = enc;
        if (checksum_ok)
        {
            // normal single-file: tag == auth_tag
            ctWithTag.insert(ctWithTag.end(), auth_tag.begin(), auth_tag.end());
        } else {
            // multi-file: last 16 before checksum is more ciphertext, checksum is the real tag
            ctWithTag.insert(ctWithTag.end(), auth_tag.begin(), auth_tag.end()); // extra 16B ciphertext
            ctWithTag.insert(ctWithTag.end(), checksum.begin(),  checksum.end()); // tag
        }

        // 5) Decrypt (AES-GCM)
        std::vector<unsigned char> plaintext = gcmDecrypt(ctWithTag, aesKey, iv);
        if (plaintext.empty())
        {
            LOG_ERROR << "Decryption produced empty output";
            return false;
        }

        // 6) Try zlib decompress (msgstore is usually compressed)
        std::vector<unsigned char>& finalPlain = plaintext;
        try {
            finalPlain = decryptorUtils::zlibDecompress(plaintext);
        } catch (...) {
            // Not zlib? fine—leave plaintext as-is (could be ZIP etc.)
        }
        if (finalPlain.empty())
        {
            LOG_ERROR << "Decompression produced empty output";
            return false;
        }
        // 7) Write output
        if (!std::filesystem::exists(outputDir)) {
            std::error_code ec;
            std::filesystem::create_directories(outputDir, ec);
            if (ec)
            {
                LOG_ERROR << "Failed to create output directory: " + ec.message();
            }
            return false;
        }

        auto outputPath = outputDir / encryptedFile.stem(); // strips ".crypt15"
        decryptorUtils::writeBinaryFileSecure(outputPath, finalPlain);

        LOG_INFO << "OK: " << encryptedFile.filename().string()
                  << " -> " << outputPath.filename().string()
                  << " (" << finalPlain.size() << " bytes)\n";
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR << "Failed to decrypt " << encryptedFile.filename().string()
                  << ": " << e.what() << "\n";
        return false;
    }
}