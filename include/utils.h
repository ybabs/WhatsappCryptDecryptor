//
// Created by daniel on 6/12/25.
//

#ifndef UTILS_H
#define UTILS_H

#include <cstddef>
#include <iterator>
#include <string>
#include <filesystem>
#include <vector>
#include <chrono>

#include "Key15.h"
#include <nlohmann/json.hpp>


namespace Crypt15Constants
{
    constexpr size_t HEADER_SIZE = 191;
    constexpr size_t SALT_OFFSET = 159;
    constexpr size_t SALT_SIZE = 32;
    constexpr size_t IV_OFFSET = 31;
    constexpr size_t IV_SIZE = 16;
    constexpr size_t AES_KEY_SIZE = 32;
}

namespace MetadataConstants
{
    constexpr size_t IV_LEN = 16; // AES-CBC IV SIZE
    constexpr size_t MAC_LEN = 32; // HMCA-SHA256 size
    constexpr size_t IV_SIZE_LEN = 1;
    constexpr size_t MAC_SIZE_LEN = 1;
    constexpr size_t MIN_BLOB_SIZE = IV_SIZE_LEN + IV_LEN + MAC_SIZE_LEN + MAC_LEN;
}

namespace decryptorUtils {
    constexpr unsigned char ZERO32[32] = {0};
    struct MetadataInfo
    {
        std::string originalPath;
        std::chrono::system_clock::time_point creationTime;
    };

    std::string sizeofFmt(double num);
    std::string generateAndroidUid();
    std::string getMd5FromFile(const std::filesystem::path& path);
    std::string cropString(const std::string& str, size_t n, const std::string& ellipsis = "...");
    bool md5Equal(const std::filesystem::path& p, const std::array<unsigned char, 16>& want);
    std::string b64(const std::string& input);
    std::vector<unsigned char> encryptionLoop(const std::array<unsigned char, Key15::KEY_SIZE>& masterKey,
                                                const std::vector<unsigned char>& fileHash, size_t outputBytes);
    std::vector<unsigned char> fromHex(const std::string& input);
    std::chrono::system_clock::time_point parseISO8601(const std::string& isoString);
    std::vector<unsigned char> aesGcmEncrypt(const std::vector<unsigned char>& plaintext,
                                        const std::vector<unsigned char>& key,
                                        const std::vector<unsigned char>& iv,
                                        const std::vector<unsigned char>& aad,
                                        size_t tagLength);
    std::vector<unsigned char> aesGcmDecrypt(const std::vector<unsigned char>& ciphertext,
                                         const std::vector<unsigned char>& key,
                                         const std::vector<unsigned char>& iv,
                                         const std::vector<unsigned char>& aad = {},
                                         size_t tagLength = 16);
    std::vector<unsigned char> base64decode(const std::string& input);
    std::string base64encode(const std::vector<unsigned char>& input);
    std::vector<unsigned char> readBinaryFile(const std::filesystem::path& filePath);
    std::string readTextFile(const std::filesystem::path& filePath);
    void writeBinaryFile(const std::filesystem::path& filePath, const std::vector<unsigned char>& data);
    void writeBinaryFileSecure(const std::filesystem::path& filePath, const std::vector<unsigned char>& data);
    std::vector<unsigned char> readBinaryFileSecure(const std::filesystem::path& filePath);
    std::filesystem::file_time_type convertToFileTime(const std::chrono::system_clock::time_point& systemTime);
    MetadataInfo getMetadataInfo(const nlohmann::json& metadata);
    std::vector<unsigned char> hkdfDerive(const std::vector<unsigned char>& salt,
                                          const std::vector<unsigned char>& inputKeyMaterial,
                                          const std::string& info, size_t outputLength);
    std::vector<unsigned char> aesCbcDecrypt(const std::vector<unsigned char>& ciphertext,
                                         const std::vector<unsigned char>& key,
                                         const std::vector<unsigned char>& iv);
    std::vector<unsigned char> zlibDecompress(const std::vector<unsigned char>& compressedData);

    bool looksLikeZlib(const std::vector<unsigned char>& v);
    bool hasMagicZip(const std::vector<unsigned char>& v);
    bool hasMagicPNG(const std::vector<unsigned char>& v);
    bool hasMagicWEBP(const std::vector<unsigned char>& v);
    std::pair<const unsigned char*, std::size_t> alignBlockCipherPayload(const std::vector<unsigned char>& fileBytes, std::size_t dataOffset);
    std::vector<unsigned char> aesGcmDecryptNoAuth(const std::vector<unsigned char>& ciphertext,
                                            const std::vector<unsigned char>& key,
                                            const std::vector<unsigned char>& iv);
    std::string base64urlTobase64(const std::string& urlsafe);
    std::filesystem::file_time_type toFileTime(std::chrono::system_clock::time_point tp);
    bool ctEq(const unsigned char* a, const unsigned char* b, size_t n);
    nlohmann::json decryptMetadata(const std::string& encoded_b64,const Key15& key15);
    std::array<unsigned char, 32> hmacSha256(const unsigned char* key, size_t keyLen,
                                          const unsigned char* d1=nullptr, size_t l1=0,
                                          const unsigned char* d2=nullptr, size_t l2=0,
                                          const unsigned char* d3=nullptr, size_t l3=0);

    std::vector<unsigned char> hmacEncryptionloop(const std::array<unsigned char, Key15::KEY_SIZE>& root,
                                                    const std::vector<unsigned char>& message,
                                                    size_t output_bytes);

    inline bool hasMagicJPEG(const std::vector<unsigned char>& v) {
        return v.size() >= 3 && v[0]==0xFF && v[1]==0xD8 && v[2]==0xFF;
    }
    inline bool hasMagicMP4(const std::vector<unsigned char>& v) {
        return v.size() >= 12 && v[4]=='f' && v[5]=='t' && v[6]=='y' && v[7]=='p';
    }
    inline bool hasMagicGIF(const std::vector<unsigned char>& v) {
        return v.size() >= 6 && v[0]=='G' && v[1]=='I' && v[2]=='F' && v[3]=='8';
    }
    inline bool hasMagicOGG(const std::vector<unsigned char>& v)
    {
        return v.size()>=4 && v[0]=='O'&&v[1]=='g'&&v[2]=='g'&&v[3]=='S';
    }
    inline bool hasMagicWAV(const std::vector<unsigned char>& v)
    {
        return v.size()>=12 && v[0]=='R'&&v[1]=='I'&&v[2]=='F'&&v[3]=='F' && v[8]=='W'&&v[9]=='A'&&v[10]=='V'&&v[11]=='E';
    }
    inline bool looksLikeMedia(const std::vector<unsigned char>& v)
    {
        return hasMagicPNG(v)||hasMagicJPEG(v)||hasMagicWEBP(v)||hasMagicZip(v)||hasMagicMP4(v)||hasMagicGIF(v)||hasMagicOGG(v)||hasMagicWAV(v);
    }
}

#endif //UTILS_H
