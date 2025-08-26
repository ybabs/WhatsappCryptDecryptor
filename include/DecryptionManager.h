#include "Key15.h"
#pragma 

#include "IDecryptor.h"
#include <vector>
#include <memory>
class DecryptionManager {

    public:
        DecryptionManager();
        ~DecryptionManager() = default;
        [[nodiscard]] bool decryptDump(const std::filesystem::path& inputDir, const Key15& key, const std::filesystem::path& outputDir) const;
        [[nodiscard]] bool decryptFile(const std::filesystem::path& encryptedFile, const Key15& key, const std::filesystem::path& outputDir) const;

    private:
        std::vector<std::unique_ptr<IDecryptor>> mDecryptors;
        [[nodiscard]] bool shouldProcessFile(const std::filesystem::path& filePath ) const;

};