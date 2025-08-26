#include "Mcrypt1Decryptor.h"
#include <iostream>
#include "utils.h"
#include "logging.h"


bool Mcrypt1Decryptor::canDecrypt(const std::filesystem::path& encryptedFile) const
{
    if (encryptedFile.extension() != ".mcrypt1")
    {
        return false;
    }
    // We need the metadata for decryption
    auto metadataFile = encryptedFile;
    metadataFile.replace_extension(".mcrypt1-metadata");
    return std::filesystem::exists(metadataFile);
}


//TODO: Refactor this into separate functions for each decryption stage
bool Mcrypt1Decryptor::decrypt(const std::filesystem::path& encryptedFile, const Key15& key, const std::filesystem::path& outputDir) const
{
    try
    {
        if (encryptedFile.empty() || outputDir.empty())
        {
            LOG_ERROR << "Mcrypt1Decryptor::decrypt: Encrypted file is empty.";
            return false;
        }

        if (!std::filesystem::exists(encryptedFile))
        {
            LOG_ERROR << "Mcrypt1Decryptor::decrypt: Encrypted file does not exist";
            return false;
        }

        if (!std::filesystem::is_directory(outputDir))
        {
            std::error_code ec;
            std::filesystem::create_directories(outputDir, ec);
            if (ec)
            {
                LOG_ERROR << "Mcrypt1Decryptor::decrypt: Failed to create output directory." + outputDir.string() + ec.message();
                return false;
            }
        }

        // Extract hash and validate file hash from file name
        std::string hexHash = encryptedFile.stem().string();
        if (hexHash.empty())
        {
            LOG_ERROR << "Mcrypt1Decryptor::decrypt: Cannot extract hash from filename." + encryptedFile.string();
            return false;
        }

        std::vector<unsigned char> fileHash;
        try
        {
            fileHash = decryptorUtils::fromHex(hexHash);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR << "Invalid hex string in filename: " + std::string(e.what());
            return false;
        }

        if (fileHash.empty())
        {
            LOG_ERROR << "File Hash cannot be empty";
            return false;
        }

        std::filesystem::path outputPath;
        std::filesystem::file_time_type fsTime{};
        {
            // Read and Decrypt Metadata
            std::filesystem::path metadataPath = encryptedFile;
            metadataPath.replace_extension(".mcrypt1-metadata");

            if (std::filesystem::exists(metadataPath))
            {
                try
                {
                    const std::string encodedMetadata = decryptorUtils::readTextFile(metadataPath);
                    const nlohmann::json metadata = decryptorUtils::decryptMetadata(encodedMetadata, key);

                    decryptorUtils::MetadataInfo metaInfo = decryptorUtils::getMetadataInfo(metadata);
                    outputPath = outputDir/ std::filesystem::path(metaInfo.originalPath);

                    fsTime = decryptorUtils::toFileTime(metaInfo.creationTime);
                }
                catch (const std::exception& e) {
                // If metadata fails, fall back to filename-only in outputDir
                    PLOG_ERROR << "[warn] Failed to decrypt/read metadata for "
                          << encryptedFile.filename() << ": " << e.what() << "\n";
                }
            }
        }

        if (outputPath.empty())
        {
            // Fallback: drop the .mcrypt1 extension and place in outputDir keeping relative name
            auto base = encryptedFile.filename();
            base.replace_extension("");
            outputPath = outputDir / base;
        }

        // Read ciphertext
        const std::vector<unsigned char> cipherText = decryptorUtils::readBinaryFile(encryptedFile);
        struct Variant { std::string name; std::vector<unsigned char> key, iv; };
        std::vector<Variant> candidates;
        candidates.reserve(4);

        // A*: Existing SHA-256 chain KDF
        {
            auto derived = decryptorUtils::encryptionLoop(key.getRoot(), fileHash, 48);
            std::vector<unsigned char> k(derived.begin(), derived.begin()+32);
            std::vector<unsigned char> iv16(derived.begin()+32, derived.begin()+48);
            std::vector<unsigned char> iv12(iv16.begin(), iv16.begin()+12);
            candidates.push_back({"SHAchain-16", k, iv16});
            candidates.push_back({"SHAchain-12", k, iv12});
        }

        // B*: WA HMAC loop KDF
        {
            auto derived = decryptorUtils::hmacEncryptionloop(key.getRoot(), fileHash, 48);
            std::vector<unsigned char> k(derived.begin(), derived.begin()+32);
            std::vector<unsigned char> iv16(derived.begin()+32, derived.begin()+48);
            std::vector<unsigned char> iv12(iv16.begin(), iv16.begin()+12);
            candidates.push_back({"WAhmac-16", k, iv16});
            candidates.push_back({"WAhmac-12", k, iv12});
        }

        std::vector<unsigned char> bestPlain;
        std::string bestName;
        bool matched = false;
        std::string previewHex;

        for (const auto& v : candidates)
        {
            try {
                    auto pt = decryptorUtils::aesGcmDecryptNoAuth(cipherText, v.key, v.iv);
                    // some media might be zlib’d; if so, inflate it
                    if (decryptorUtils::looksLikeZlib(pt))
                    {
                        try
                        {
                            pt = decryptorUtils::zlibDecompress(pt);
                        } catch (...) { /* ignore */ }
                    }

                    if (decryptorUtils::looksLikeMedia(pt)) {
                        bestPlain = std::move(pt);
                        bestName = v.name;
                        matched = true;
                        break;
                    }

                    // keep first successful decrypt as fallback preview
                    if (bestPlain.empty() && !pt.empty()) {
                        bestPlain = pt;
                        // hex preview of first 16
                        std::ostringstream oss;
                        for (size_t i=0; i< std::min<size_t>(16, pt.size()); ++i)
                        {
                            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pt[i]);
                        }
                        previewHex = oss.str();
                        bestName = v.name + " (no-magic)";
                    }
                } catch (const std::exception& e)
                    {
                      // try next
                    }
        }

        if (bestPlain.empty()) {
            LOG_ERROR << "Decryption produced no plaintext for any KDF/IV variant";
            return false;
        }

        // Write output
        decryptorUtils::writeBinaryFile(outputPath, bestPlain);

        if (matched)
        {
            LOG_INFO << "mcrypt1 data decrypted via " << bestName << "\n";
        } else
        {
            PLOG_WARNING << "Decrypted via " << bestName
                      << " but magic not recognized; first16=" << previewHex << "\n";
        }


        // Set timestamp if we got one from metadata
        if (fsTime.time_since_epoch().count() != 0)
        {
            std::error_code ec;
            std::filesystem::last_write_time(outputPath, fsTime, ec);
            if (ec)
            {
                PLOG_WARNING << "Warning: Could not set file timestamp for " << outputPath << ": " << ec.message() << std::endl;
            }
        }

                PLOG_INFO << "Successfully decrypted: " << encryptedFile.filename()
                          << " -> " << outputPath << std::endl;
                return true;
            }
            catch (const std::exception& e)
            {
                PLOG_ERROR << "Failed to decrypt " << encryptedFile.filename() << ": " << e.what() << std::endl;
                return false;
            }
            catch (...)
            {
                PLOG_ERROR << "Failed to decrypt " << encryptedFile.filename() << ": Unknown error" << std::endl;
                return false;
            }


}

