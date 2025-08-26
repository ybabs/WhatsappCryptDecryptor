#pragma once
#include <cstddef>
#include <vector>
#include <array>
#include <string>

class Key15{
    public:
        static constexpr size_t KEY_SIZE = 32;
        static constexpr size_t HEX_STRING_SIZE = 64;
        Key15() = default;
        explicit Key15(const std::vector<char>& keyBytes);
        explicit Key15(const std::string& keyString);
        [[nodiscard]] const std::array<unsigned char, KEY_SIZE>& getRoot() const;
        static Key15 fromHexString(const std::string& hexString);
        [[nodiscard]] std::string toHexString() const;
        [[nodiscard]] bool isValid() const;
        [[nodiscard]] std::array<unsigned char, KEY_SIZE> get() const;
        [[nodiscard]] std::array<unsigned char, KEY_SIZE> getMetadataEncryption() const;
        [[nodiscard]] std::array<unsigned char, KEY_SIZE> getMetadataAuthentication() const;

    private:
        std::array<unsigned char, KEY_SIZE> mKey;
        static std::vector<unsigned char> hexStringToBytes(const std::string& hexString);
        static std::string bytesToHexString(const std::array<unsigned char, KEY_SIZE>& bytes);

        // HMAC Encryption Loop
        static std::array<unsigned char, KEY_SIZE> hmacEncryptionLoop(const std::array<unsigned char, KEY_SIZE>& root,
                         const unsigned char* message, size_t messageLen);
};
