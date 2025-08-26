#include "DecryptionManager.h"
#include "Mcrypt1Decryptor.h"
#include "Crypt15Decryptor.h"
#include "logging.h"
#include <filesystem>
#include <iostream>
#include <set>

DecryptionManager::DecryptionManager()
{
        mDecryptors.emplace_back(std::make_unique<Mcrypt1Decryptor>());
        mDecryptors.emplace_back(std::make_unique<Crypt15Decryptor>());
}

bool DecryptionManager::decryptFile(const std::filesystem::path& encryptedFile, const Key15& key, const std::filesystem::path& outputDir) const
{

        for (const auto& decryptor : mDecryptors)
        {
                if (decryptor->canDecrypt(encryptedFile))
                {
                        const auto result = decryptor->decrypt(encryptedFile, key, outputDir);
                        return result;
                }
        }
        return false;
}

bool DecryptionManager::decryptDump(const std::filesystem::path& inputDir, const Key15& key, const std::filesystem::path& outputDir) const
{
        if(!std::filesystem::exists(inputDir) || !std::filesystem::is_directory(inputDir))
        {
                LOG_ERROR << "Error: Input Path is not a valid directory" << inputDir << std::endl;
                return false;
        } 

        LOG_INFO << "Starting decryption of dump: " << inputDir << std::endl;
        LOG_INFO<< "Output will be saved to: " << outputDir << std::endl;

        // Create the output directory if it doesn't exist.
        std::filesystem::create_directories(outputDir);
        bool overallSuccess = true;
        size_t processedFiles = 0;
        size_t successfulFiles = 0;

        // Right, scan the entire tree
        for(const auto& entry: std::filesystem::recursive_directory_iterator(inputDir))
        {
                if(entry.is_directory())
                {
                        continue;
                }

                const auto& path = entry.path();
                if (!shouldProcessFile(path))
                {
                        continue;
                }
                const std::string fileName = path.filename().string();
                LOG_INFO << "Decrypting...." << std::endl;

                processedFiles++;
                if (decryptFile(path, key, outputDir))
                {
                        successfulFiles++;
                }
                else
                {
                        overallSuccess = false;
                        LOG_ERROR << "Failed to decrypt: " << fileName << std::endl;
                }
        }
        LOG_INFO << "Decryption complete: " << successfulFiles << "/" << processedFiles
          << " files successfully decrypted" << std::endl;
        return overallSuccess;
}

bool DecryptionManager::shouldProcessFile(const std::filesystem::path& filePath) const
{
        const std::set<std::string> ignoredExtensions = {".mcrypt1-metadata"};
        const std::set<std::string> ignoredFilenames = {"metadata.json", "files.json"};

        const std::string fileName = filePath.filename().string();
        const std::string extension = filePath.extension().string();

        if (ignoredExtensions.contains(extension) || ignoredFilenames.contains(fileName))
        {
                return false;
        }

        // Only process files that our decryptors can handle
        for (const auto& decryptor : mDecryptors)
        {
                if (decryptor->canDecrypt(filePath))
                {
                        return true;
                }
        }
        return false;
}


