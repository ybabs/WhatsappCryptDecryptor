#include "Key15.h"
#include <algorithm>
#include <stdexcept>
#include <iomanip>

#include<openssl/evp.h>
#include "utils.h"

Key15::Key15(const std::vector<char>& keyBytes): mKey()
{
    if (keyBytes.size() != KEY_SIZE)
    {
        throw std::invalid_argument("Key15 must be initialized with exactly " + std::to_string(KEY_SIZE) + " bytes.");
    }
    std::ranges::copy(keyBytes, mKey.begin());
}

Key15::Key15(const std::string& keyString) : mKey()
{
    auto keyBytes = hexStringToBytes(keyString);
    if (keyBytes.size() != KEY_SIZE)
    {
        throw std::invalid_argument("Hex string must represent exactly " +
                                  std::to_string(KEY_SIZE) + " bytes, got " +
                                  std::to_string(keyBytes.size()) + " bytes.");
    }

    std::ranges::copy(keyBytes, mKey.begin());
}


const std::array<unsigned char, Key15::KEY_SIZE>& Key15::getRoot() const
{
    return mKey;
}

Key15 Key15::fromHexString(const std::string& hexString)
{
    return Key15(hexString);
}

std::string Key15::toHexString() const
{
    return bytesToHexString(mKey);
}

bool Key15::isValid() const
{
    return std::ranges::any_of(mKey, [](unsigned char b) { return b != 0; });
}

std::vector<unsigned char> Key15::hexStringToBytes(const std::string& hexString)
{
    // Remove any whitespace or non-hex characters
    std::string cleanHex;
    for (const char c : hexString)
    {
        if (std::isxdigit(c))
        {
            cleanHex += c;
        }
    }

    if (cleanHex.length() != HEX_STRING_SIZE)
    {
        throw std::invalid_argument("Hex string must be exactly " +
                                  std::to_string(HEX_STRING_SIZE) +
                                  " characters long, got " +
                                  std::to_string(cleanHex.length()));
    }

    std::vector<unsigned char> bytes;
    bytes.reserve(KEY_SIZE);

    for (size_t i = 0; i < cleanHex.length(); i += 2)
    {
        std::string byteString = cleanHex.substr(i, 2);
        auto byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

std::string Key15::bytesToHexString(const std::array<unsigned char, KEY_SIZE>& bytes)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (unsigned char byte : bytes)
    {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::array<unsigned char, Key15::KEY_SIZE> Key15::hmacEncryptionLoop(const std::array<unsigned char, KEY_SIZE>& root, const unsigned char* message, size_t messageLen)
{
    auto privateKey = decryptorUtils::hmacSha256(decryptorUtils::ZERO32, sizeof(decryptorUtils::ZERO32), root.data(), root.size());
    const unsigned char iCounter = 0x01;
    // data_prev is empty on first iteration, so omit it
    auto digest = decryptorUtils::hmacSha256(privateKey.data(), privateKey.size(), nullptr, 0, message, messageLen, &iCounter, 1);
    return digest;
}

std::array<unsigned char, Key15::KEY_SIZE> Key15::get() const
{
    static const char kMsg[] = "backup encryption";
    return hmacEncryptionLoop(mKey, reinterpret_cast<const unsigned char*>(kMsg),sizeof(kMsg) - 1);
}

std::array<unsigned char, Key15::KEY_SIZE> Key15::getMetadataEncryption() const
{
    static const char kMsg[] = "metadata encryption";
    return hmacEncryptionLoop(mKey, reinterpret_cast<const unsigned char*>(kMsg),sizeof(kMsg) - 1);
}
std::array<unsigned char, Key15::KEY_SIZE> Key15::getMetadataAuthentication() const
{
    static const char kMsg[] = "metadata authentication";
    return hmacEncryptionLoop(mKey, reinterpret_cast<const unsigned char*>(kMsg),sizeof(kMsg) - 1);
}