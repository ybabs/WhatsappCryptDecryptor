#include "IDecryptor.h"
#include "Key15.h"



class Mcrypt1Decryptor : public IDecryptor
{
public:
    Mcrypt1Decryptor() = default;
    ~Mcrypt1Decryptor() override = default;

    [[nodiscard]] bool canDecrypt(const std::filesystem::path& encryptedFile) const override;
    [[nodiscard]] bool decrypt(const std::filesystem::path& encryptedFile,
                 const Key15& key, 
                 const std::filesystem::path& outputDir) const override;
};
