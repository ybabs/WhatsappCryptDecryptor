//
// Created by daniel on 6/12/25.
//

#include "utils.h"

#include <format>
#include <fstream>
#include <random>
#include <cryptopp/filters.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <zlib.h>
#include <cryptopp/base64.h>
#include <date/date.h>
#include <iostream>
#include <openssl/core_names.h>   // OSSL_ALG_PARAM_DIGEST
#include <openssl/params.h>       // OSSL_PARAM_*

static_assert(SHA256_DIGEST_LENGTH == 32, "SHA256 Digest Length is not 32 Bytes!");

namespace decryptorUtils
{
    std::string sizeofFmt(double num)
    {
        const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"};
        int i = 0;
        for (i = 0; num >= 1024.0 && i < std::size(units) - 1; i++)
        {
            num /= 1024.0;
        }

        return std::format("{:.1f} {}", num, units[i]);
    }

    std::string generateAndroidUid()
    {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        uint64_t rnd = gen();
        return std::format("{:016x}", rnd);
    }

    std::string getMd5FromFile(const std::filesystem::path& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open())
        {
            throw std::runtime_error("Could not open file" + path.string());
        }

        EVP_MD_CTX* mdContext = EVP_MD_CTX_new();
        if (!mdContext)
        {
            throw std::runtime_error("Could not create MD5 OpenSSL context");
        }

        if (EVP_DigestInit_ex(mdContext, EVP_md5(), nullptr) != 1)
        {
            EVP_MD_CTX_free(mdContext);
            throw std::runtime_error("Could not initialise OpenSSL MD5 Context");
        }

        char buffer[8192];
        while (file.read(buffer, sizeof(buffer)))
        {
            if (EVP_DigestUpdate(mdContext, buffer, file.gcount()) != 1)
            {
                EVP_MD_CTX_free(mdContext);
                throw std::runtime_error("Failed to update OpenSSL MD5 Hash");
            }
        }

        if (file.gcount() > 0)
        {
            if (EVP_DigestUpdate(mdContext, buffer, file.gcount()) != 1)
            {
                EVP_MD_CTX_free(mdContext);
                throw std::runtime_error("Could not update OpenSSL MD5 Hash on final chunk");
            }
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen;
        if (EVP_DigestFinal_ex(mdContext, hash, &hashLen) != 1)
        {
            EVP_MD_CTX_free(mdContext);
            throw std::runtime_error("Could not finalize OpenSSL MD5 Hash");
        }

        EVP_MD_CTX_free(mdContext);
        return std::string(reinterpret_cast<char*>(hash), hashLen);
    }

    std::string cropString(const std::string& str, size_t n, const std::string& ellipsis)
    {
        if (str.length() > n)
        {
            return ellipsis + str.substr(str.length() - (n - ellipsis.length()));
        }

        return str;
    }

    bool md5Equal(const std::filesystem::path& p, const std::array<unsigned char, 16>& want)
    {
        std::ifstream file(p, std::ios::binary);
        if (!file)
        {
            return false;
        }

        EVP_MD_CTX* context = EVP_MD_CTX_new();
        if (!context)
        {
            return false;
        }

        if (EVP_DigestInit_ex(context, EVP_md5(), nullptr) != 1)
        {
            EVP_MD_CTX_free(context);
            return false;
        }

        std::array<char, 8192> buffer{};
        while (file.good())
        {
            file.read(buffer.data(), buffer.size());
            std::streamsize bytesRead = file.gcount();
            if (bytesRead > 0)
            {
                if (EVP_DigestUpdate(context, reinterpret_cast<const unsigned char*>(buffer.data()),
                                     static_cast<size_t>(bytesRead)) != 1)
                {
                    EVP_MD_CTX_free(context);
                    return false;
                }
            }
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> mdValue{};
        unsigned int mdLen = 0;
        if (EVP_DigestFinal_ex(context, mdValue.data(), &mdLen) != 1)
        {
            EVP_MD_CTX_free(context);
            return false;
        }

        EVP_MD_CTX_free(context);
        if (mdLen != want.size())
        {
            return false;
        }

        return std::equal(want.begin(), want.end(), mdValue.begin());
    }

    std::string b64(const std::string& input)
    {
        std::string temp = input;
        for (char& c : temp)
        {
            if (c == '-')
            {
                c = '+';
            }
        }

        for (char& c : temp)
        {
            if (c == '_')
            {
                c = '/';
            }
        }

        while (temp.size() % 4)
        {
            temp.push_back('=');
        }

        std::string out;
        CryptoPP::StringSource ss(temp, true,
                                  new CryptoPP::Base64Decoder(new CryptoPP::StringSink(out)));
        return out;
    }

    std::vector<unsigned char> encryptionLoop(const std::array<unsigned char, Key15::KEY_SIZE>& masterKey,
                                              const std::vector<unsigned char>& fileHash, size_t outputBytes)
    {
        if (outputBytes == 0)
        {
            return {};
        }

        std::vector<unsigned char> output;
        output.reserve(outputBytes + SHA256_DIGEST_LENGTH);
        unsigned char digest[SHA256_DIGEST_LENGTH];

        // Create EVP context with automatic cleanup
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!ctx)
        {
            throw std::runtime_error("Could not create EVP_MD_CTX");
        }

        // Initialize with SHA256
        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        {
            throw std::runtime_error("Could not initialize SHA256 digest");
        }

        // Create the first hash SHA256(masterKey + fileHash)
        if (EVP_DigestUpdate(ctx.get(), masterKey.data(), masterKey.size()) != 1)
        {
            throw std::runtime_error("Could not update digest with master key");
        }

        if (EVP_DigestUpdate(ctx.get(), fileHash.data(), fileHash.size()) != 1)
        {
            throw std::runtime_error("Could not update digest with file hash");
        }

        unsigned int digestLen = 0;
        if (EVP_DigestFinal_ex(ctx.get(), digest, &digestLen) != 1)
        {
            throw std::runtime_error("Could not finalize digest");
        }

        // Verify we got the expected digest length
        if (digestLen != SHA256_DIGEST_LENGTH)
        {
            throw std::runtime_error("Unexpected digest length");
        }

        // Append first digest to the output
        output.insert(output.end(), digest, digest + SHA256_DIGEST_LENGTH);

        while (output.size() < outputBytes)
        {
            // Rehash the previous digest: SHA256(digest)
            if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
            {
                throw std::runtime_error("Could not initialize SHA256 digest in loop");
            }

            if (EVP_DigestUpdate(ctx.get(), digest, SHA256_DIGEST_LENGTH) != 1)
            {
                throw std::runtime_error("Could not update digest in loop");
            }

            if (EVP_DigestFinal_ex(ctx.get(), digest, &digestLen) != 1)
            {
                throw std::runtime_error("Could not finalize digest in loop");
            }

            output.insert(output.end(), digest, digest + SHA256_DIGEST_LENGTH);
        }

        output.resize(outputBytes);
        return output;
    }

    std::vector<unsigned char> fromHex(const std::string& input)
    {
        std::vector<unsigned char> output;

        if (input.length() % 2 != 0)
        {
            throw std::invalid_argument("Invalid hex string : must be a multiple of 2");
        }

        for (unsigned int i = 0; i < input.length(); i += 2)
        {
            std::string hex = input.substr(i, 2);
            auto byte = static_cast<unsigned char>(strtol(hex.c_str(), nullptr, 16));
            output.push_back(byte);
        }

        return output;
    }

    std::chrono::system_clock::time_point parseISO8601(const std::string& isoString)
    {
        std::string s = isoString;
        if (!s.empty() && s.back() == 'Z') s.pop_back();

        std::stringstream ss(s);
        std::chrono::system_clock::time_point tp;
        ss >> date::parse("%Y-%m-%dT%H:%M:%S", tp);
        if (ss.fail()) {
            // Try fractional seconds
            ss.clear();
            ss.str(s);
            ss >> date::parse("%Y-%m-%dT%H:%M:%S%F", tp);
            if (ss.fail()) throw std::runtime_error("Failed to parse ISO 8601 timestamp: " + isoString);
        }
        return tp;
    }

    std::vector<unsigned char> aesGcmDecrypt(const std::vector<unsigned char>& ciphertext,
                                             const std::vector<unsigned char>& key,
                                             const std::vector<unsigned char>& iv,
                                             const std::vector<unsigned char>& aad,
                                             size_t tagLength)
    {
        // Input validation
        if (ciphertext.size() < tagLength)
        {
            throw std::runtime_error("Ciphertext is too short to contain a GCM tag of size " +
                std::to_string(tagLength));
        }

        // Validate key size and determine AES variant
        const EVP_CIPHER* cipher;
        switch (key.size())
        {
        case 16: cipher = EVP_aes_128_gcm();
            break;
        case 24: cipher = EVP_aes_192_gcm();
            break;
        case 32: cipher = EVP_aes_256_gcm();
            break;
        default:
            throw std::runtime_error("Invalid key size: " + std::to_string(key.size()) +
                ". Must be 16, 24, or 32 bytes.");
        }

        // Validate IV length (12 bytes is recommended for GCM)
        if (iv.empty() || iv.size() > 16)
        {
            throw std::runtime_error("Invalid IV length: " + std::to_string(iv.size()) +
                ". Should be 1-16 bytes, preferably 12.");
        }

        // Validate tag length
        if (tagLength < 12 || tagLength > 16)
        {
            throw std::runtime_error("Invalid tag length: " + std::to_string(tagLength) +
                ". Must be 12-16 bytes.");
        }

        // Extract tag and encrypted data
        const unsigned char* tag = ciphertext.data() + ciphertext.size() - tagLength;
        const unsigned char* encryptedData = ciphertext.data();
        int encryptedLen = static_cast<int>(ciphertext.size() - tagLength);

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

        if (!ctx)
        {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }
        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) != 1)
        {
            throw std::runtime_error("Failed to initialize AES-GCM decryption");
        }

        // Set IV length
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1)
        {
            throw std::runtime_error("Failed to set IV length");
        }

        // Set key and IV
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1)
        {
            throw std::runtime_error("Failed to set key and IV");
        }

        std::vector<unsigned char> plaintext(encryptedLen);
        int plaintextLen = 0;
        int len = 0;

        // Process AAD if provided
        if (!aad.empty())
        {
            if (EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(), aad.size()) != 1)
            {
                throw std::runtime_error("Failed to process Additional Authenticated Data");
            }
        }

        // Decrypt the data
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, encryptedData, encryptedLen) != 1)
        {
            throw std::runtime_error("Decryption failed");
        }
        plaintextLen = len;

        // Set the expected tag
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tagLength, const_cast<unsigned char*>(tag)) != 1)
        {
            throw std::runtime_error("Failed to set authentication tag");
        }

        // Finalize and verify authentication tag
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1)
        {
            throw std::runtime_error("Authentication verification failed. Data may be corrupted or key incorrect.");
        }

        plaintextLen += len;
        plaintext.resize(plaintextLen);

        return plaintext;
    }

    std::vector<unsigned char> aesGcmDecryptNoAuth(const std::vector<unsigned char>& ciphertext,
                                    const std::vector<unsigned char>& key,
                                    const std::vector<unsigned char>& iv)
    {
        const size_t TAG_LEN = 16;

        if (ciphertext.size() < TAG_LEN)
        {
            throw std::runtime_error("Ciphertext too short for GCM (missing tag)");
        }

        const size_t encLen = ciphertext.size() - TAG_LEN;
        const unsigned char* tag = ciphertext.data() + encLen;
        const EVP_CIPHER* cipher = nullptr;

        switch (key.size())
        {
            case 16: cipher = EVP_aes_128_gcm(); break;
            case 24: cipher = EVP_aes_192_gcm(); break;
            case 32: cipher = EVP_aes_256_gcm(); break;
            default:
                throw std::runtime_error("Invalid key size for GCM: " + std::to_string(key.size()));
        }

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        if (!ctx)
        {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }

        if (EVP_DecryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr) != 1)
            throw std::runtime_error("Failed to init AES-GCM");
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1)
            throw std::runtime_error("Failed to set IV length");
        if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("Failed to set key/iv");

        std::vector<unsigned char> plaintext(encLen);
        int outl = 0;

        // Decrypt only the actual ciphertext (without the tag)
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outl,
                              ciphertext.data(), (int)encLen) != 1)
            throw std::runtime_error("GCM decrypt update failed");

        int total = outl;

        // Set the tag but don't verify it (since we want "no auth")
        if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, (int)TAG_LEN, const_cast<unsigned char*>(tag)) != 1)
        {
            throw std::runtime_error("Failed to set GCM tag");
        }

        int dummy = 0;
        EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total, &dummy);

        plaintext.resize(total);
        return plaintext;
    }

    std::vector<unsigned char> aesGcmEncrypt(const std::vector<unsigned char>& plaintext,
                                        const std::vector<unsigned char>& key,
                                        const std::vector<unsigned char>& iv,
                                        const std::vector<unsigned char>& aad,
                                        size_t tagLength)
    {
        const EVP_CIPHER* cipher;
        switch (key.size())
        {
            case 16: cipher = EVP_aes_128_gcm(); break;
            case 24: cipher = EVP_aes_192_gcm(); break;
            case 32: cipher = EVP_aes_256_gcm(); break;
            default: throw std::runtime_error("Invalid key size");
        }

        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

        if (!ctx)
        {
            throw std::runtime_error("Failed to create context");
        }

        EVP_EncryptInit_ex(ctx.get(), cipher, nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data());

        std::vector<unsigned char> ciphertext(plaintext.size() + tagLength);
        int len = 0;
        int ciphertextLen = 0;

        if (!aad.empty())
        {
            EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(), aad.size());
        }

        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size());
        ciphertextLen = len;

        EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len);
        ciphertextLen += len;

        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tagLength, ciphertext.data() + ciphertextLen);

        ciphertext.resize(ciphertextLen + tagLength);
        return ciphertext;
    }

    std::vector<unsigned char> base64decode(const std::string& input)
    {
        if (input.empty())
        {
            throw std::runtime_error("Empty input string");
        }

        std::unique_ptr<EVP_ENCODE_CTX, decltype(&EVP_ENCODE_CTX_free)>ctx(EVP_ENCODE_CTX_new(), EVP_ENCODE_CTX_free);

        if (!ctx)
        {
            throw std::runtime_error("Failed to create EVP_ENCODE_CTX");
        }
        EVP_DecodeInit(ctx.get());
        std::vector<unsigned char> decoded;
        decoded.reserve((input.size() * 3) / 4 + 3); // +3 for padding

        int outLen = 0;
        int finalLen = 0;

        // Temporary buffer for decoding chunks
        std::vector<unsigned char> tempBuffer(input.size());

        // Decode the data
        int result = EVP_DecodeUpdate(ctx.get(), tempBuffer.data(), &outLen, reinterpret_cast<const unsigned char*>(input.data()),
                                      static_cast<int>(input.size()));

        if (result < 0)
        {
            throw std::runtime_error("Base64 decoding failed: invalid characters");
        }

        // Finalize decoding
        if (EVP_DecodeFinal(ctx.get(), tempBuffer.data() + outLen, &finalLen) != 1)
        {
            throw std::runtime_error("Base64 decoding failed: invalid padding or format");
        }

        int totalLen = outLen + finalLen;
        decoded.assign(tempBuffer.begin(), tempBuffer.begin() + totalLen);
        return decoded;
    }

    // For Testing
    std::string base64encode(const std::vector<unsigned char>& input)
    {
        if (input.empty())
        {
            return "";
        }
        std::unique_ptr<EVP_ENCODE_CTX, decltype(&EVP_ENCODE_CTX_free)>ctx(EVP_ENCODE_CTX_new(), EVP_ENCODE_CTX_free);
        
        if (!ctx) throw std::runtime_error("Failed to create context");
        
        EVP_EncodeInit(ctx.get());
        
        int groups     = (input.size() + 2) / 3;
        int rawLen     = groups * 4;               
        int lineBreaks = (rawLen + 63) / 64;  
         // +1 for the final '\n' from EVP_EncodeFinal
        // +1 for the NULL terminator
        int maxLen     = rawLen + lineBreaks + 1 + 1;
        std::vector<char> encoded(maxLen);
        
        int outLen = 0;
        EVP_EncodeUpdate(ctx.get(), reinterpret_cast<unsigned char*>(encoded.data()), &outLen, input.data(), input.size());
        
        int finalLen = 0;
        EVP_EncodeFinal(ctx.get(), reinterpret_cast<unsigned char*>(encoded.data() + outLen), &finalLen);
        
        int totalLen = outLen + finalLen;
        
        // Remove newlines that OpenSSL adds
        std::string result;
        for (int i = 0; i < totalLen; ++i) {
            if (encoded[i] != '\n' && encoded[i] != '\0') {
                result += encoded[i];
            }
        }
        
        return result;
    }

    std::vector<unsigned char> readBinaryFile(const std::filesystem::path& filePath)
    {
        if (!std::filesystem::exists(filePath))
        {
            throw std::runtime_error("File does not exist: " + filePath.string());
        }

        std::ifstream file(filePath, std::ios::binary);

        if (!file)
        {
            throw std::runtime_error("Failed to open file: " + filePath.string());
        }

        std::vector<unsigned char> data;
        auto fileSize = std::filesystem::file_size(filePath);
        data.resize(fileSize);
        file.read(reinterpret_cast<char*>(data.data()), fileSize);

        if (!file)
        {
            throw std::runtime_error("Failed to read file: " + filePath.string());
        }

        return data;
    }

    std::string readTextFile(const std::filesystem::path& filePath)
    {
        if (!std::filesystem::exists(filePath))
        {
            throw std::runtime_error("File does not exist: " + filePath.string());
        }
        std::ifstream file(filePath);
        if (!file)
        {
            throw std::runtime_error("Failed to open file: " + filePath.string());
        }
        std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        if (contents.empty())
        {
            throw std::runtime_error("File Contents are empty: " + filePath.string());
        }

        return contents;
    }

    void writeBinaryFile(const std::filesystem::path& filePath, const std::vector<unsigned char>& data)
    {
        if (data.empty())
        {
            throw std::runtime_error("Data does not exist, Cannot write to: " + filePath.string());
        }

        auto parentDir = filePath.parent_path();
        if (!parentDir.empty())
        {
            std::error_code ec;
            std::filesystem::create_directories(parentDir, ec);
            if (ec)
            {
                throw std::runtime_error("Failed to create directory: " + parentDir.string() + " - " + ec.message());
            }
        }

        std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
        if (!file)
        {
            throw std::runtime_error("Failed to open file for writing: " + filePath.string());
        }

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        if (!file)
        {
            throw std::runtime_error("Failed to write to file: " + filePath.string());
        }
    }

    // Safe timestamp conversion. Handle potential time difference between two clocks
    std::filesystem::file_time_type convertToFileTime(const std::chrono::system_clock::time_point& systemTime)
    {
        return std::chrono::clock_cast<std::filesystem::file_time_type::clock>(systemTime);
    }

    MetadataInfo getMetadataInfo(const nlohmann::json& metadata)
    {
        MetadataInfo info;

        if (!metadata.contains("name") || !metadata["name"].is_string())
        {
            throw std::runtime_error("Metadata does not have a name field");
        }

        info.originalPath = metadata["name"].get<std::string>();

        if (info.originalPath.empty())
        {
            throw std::runtime_error("Metadata does not have a original path and it cannot be empty");
        }

        if (!metadata.contains("updateTime") || !metadata["updateTime"].is_string())
        {
            throw std::runtime_error("Metadata does not have a updateTime field");
        }

        std::string updateTimeString = metadata["updateTime"].get<std::string>();
        if (updateTimeString.empty())
        {
            throw std::runtime_error("Metadata does not have a updateTime field and cannot be empty");
        }

        try
        {
            info.creationTime = parseISO8601(updateTimeString);
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error("Failed to parse metadata updateTime: " + std::string(e.what()));
        }

        return info;
    }

    std::vector<unsigned char> hkdfDerive(const std::vector<unsigned char>& salt,
                                          const std::vector<unsigned char>& inputKeyMaterial,
                                          const std::string& info,
                                          size_t outputLength)
    {
        if (salt.empty())
        {
            throw std::runtime_error("HKDF Salt is empty");
        }

        if (inputKeyMaterial.empty())
        {
            throw std::runtime_error("HKDF Input Key Material is empty");
        }

        // RFC 5869 Limit
        if (outputLength == 0 || outputLength > 255 * 32)
        {
            throw std::runtime_error("Invalid HKDF Output Length " + std::to_string(outputLength));
        }

        std::vector<unsigned char> derivedKey(outputLength);
        size_t actualOutputLength = outputLength;

        std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>
            pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);

        if (!pctx)
        {
            throw std::runtime_error("Failed to create EVP_PKEY_CTX for HKDF");
        }

        // Initialize HKDF context
        if (EVP_PKEY_derive_init(pctx.get()) <= 0)
        {
            throw std::runtime_error("HKDF initialization failed");
        }

        // Set hash function to SHA-256
        if (EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) <= 0)
        {
            throw std::runtime_error("Failed to set HKDF hash function to SHA-256");
        }

        // Set salt
        if (EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), salt.data(), salt.size()) <= 0)
        {
            throw std::runtime_error("Failed to set HKDF salt");
        }

        // Set input key material
        if (EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), inputKeyMaterial.data(), inputKeyMaterial.size()) <= 0)
        {
            throw std::runtime_error("Failed to set HKDF input key material");
        }

        // Set info parameter
        if (!info.empty()) {
            if (EVP_PKEY_CTX_add1_hkdf_info(pctx.get(),
                                           reinterpret_cast<const unsigned char*>(info.c_str()),
                                           info.size()) <= 0) {
                throw std::runtime_error("Failed to set HKDF info parameter");
                                           }
        }

        // Derive the key
        if (EVP_PKEY_derive(pctx.get(), derivedKey.data(), &actualOutputLength) <= 0) {
            throw std::runtime_error("HKDF key derivation failed");
        }

        if (actualOutputLength != outputLength) {
            throw std::runtime_error("HKDF produced unexpected output length: " +
                                   std::to_string(actualOutputLength) + " (expected " +
                                   std::to_string(outputLength) + ")");
        }

        return derivedKey;
    }

    std::vector<unsigned char> aesCbcDecrypt(const std::vector<unsigned char>& ciphertext,
                                            const std::vector<unsigned char>& key,
                                            const std::vector<unsigned char>& iv) 
    {
        // Input validation
        if (ciphertext.empty()) {
            throw std::runtime_error("Ciphertext cannot be empty");
        }
        if (key.size() != 32) {
            throw std::runtime_error("AES-256 requires a 32-byte key, got " + std::to_string(key.size()));
        }
        if (iv.size() != 16) {
            throw std::runtime_error("AES-CBC requires a 16-byte IV, got " + std::to_string(iv.size()));
        }
        if (ciphertext.size() % 16 != 0) {
            throw std::runtime_error("Ciphertext length must be multiple of 16 bytes for AES-CBC");
        }

        // Use RAII for automatic cleanup
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
            ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }

        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            throw std::runtime_error("AES-256-CBC initialization failed");
        }

        // Prepare output buffer
        std::vector<unsigned char> plaintext(ciphertext.size() + 16); // Extra space for padding
        int len = 0;
        int plaintextLen = 0;

        // Decrypt the data
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                             ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
            throw std::runtime_error("AES decryption failed");
        }
        plaintextLen = len;

        // Finalize decryption (handles padding removal)
        if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len) != 1) {
            throw std::runtime_error("AES decryption finalization failed (invalid padding or key)");
        }
        plaintextLen += len;

        plaintext.resize(plaintextLen);
        return plaintext;
    }

    std::vector<unsigned char> zlibDecompress(const std::vector<unsigned char>& compressedData)
    {
        if (compressedData.empty())
        {
            throw std::runtime_error("Compressed data is empty");
        }

        const size_t chunkSize = 65536; // 64KB Size for better performance
        const size_t maxDecompressedSize = 10 * 1024 * 1024 * 1024ULL; // 10GB limit

        z_stream stream {};
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        stream.avail_in = static_cast<uInt>(compressedData.size());
        stream.next_in = const_cast<Bytef*>(compressedData.data());

        // initialise zlib for decompression
        int ret = inflateInit(&stream);
        if (ret != Z_OK)
        {
            throw std::runtime_error("Failed to initialize zlib with code" + std::to_string(ret));
        }

        struct ZlibCleanup
        {
            z_stream* mStream;
            ~ZlibCleanup() {if (mStream) inflateEnd(mStream);}
        } cleanup(&stream);

        std::vector<unsigned char> decompressedData;
        std::vector<unsigned char> buffer(chunkSize);
        size_t totalDecompressed = 0;

        do
        {
            stream.avail_out = static_cast<uInt>(chunkSize);
            stream.next_out = buffer.data();

            ret = inflate(&stream, Z_NO_FLUSH);
            switch (ret)
            {
                case Z_STREAM_ERROR:
                    throw std::runtime_error("Inflate failed");
                case Z_NEED_DICT:
                    throw std::runtime_error("Inflate returned Z_NEED_DICT");
                case Z_DATA_ERROR:
                    throw std::runtime_error("Inflate returned Z_DATA_ERROR");
                case Z_MEM_ERROR:
                    throw std::runtime_error("Inflate returned Z_MEM_ERROR");
            case Z_OK:
            case Z_STREAM_END:
                break;
            default:
                throw std::runtime_error("Inflate failed zlib error with code: " + std::to_string(ret));
            }
            const size_t have = chunkSize - stream.avail_out;
            totalDecompressed+=have;

            if (totalDecompressed > maxDecompressedSize)
            {
                throw std::runtime_error("Decompression failed: Data exceed maximum size limit");
            }

            decompressedData.insert(decompressedData.end(), buffer.begin(), buffer.begin() + have);

        } while (stream.avail_out == 0 && ret != Z_STREAM_END);

        if (ret != Z_STREAM_END)
        {
            throw std::runtime_error("zlib deomcpression incomplete");
        }

        return decompressedData;
    }

    std::vector<unsigned char> readBinaryFileSecure(const std::filesystem::path& filePath)
    {
        if (!std::filesystem::exists(filePath)) {
            throw std::runtime_error("File does not exist: " + filePath.string());
        }

        auto fileSize = std::filesystem::file_size(filePath);
        if (fileSize == 0) {
            throw std::runtime_error("File is empty: " + filePath.string());
        }

        if (fileSize < Crypt15Constants::HEADER_SIZE) {
            throw std::runtime_error("File too small to be valid Crypt15 format (" +
                                   std::to_string(fileSize) + " bytes, minimum " +
                                   std::to_string(Crypt15Constants::HEADER_SIZE) + ")");
        }

        std::ifstream file(filePath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file for reading: " + filePath.string());
        }

        std::vector<unsigned char> data(fileSize);
        file.read(reinterpret_cast<char*>(data.data()), fileSize);

        if (!file) {
            throw std::runtime_error("Failed to read file completely: " + filePath.string());
        }

        return data;
    }

    void writeBinaryFileSecure(const std::filesystem::path& filePath, const std::vector<unsigned char>& data)
    {
        if (data.empty()) {
            throw std::runtime_error("Cannot write empty data to file: " + filePath.string());
        }

        // Create directories if they don't exist
        auto parentDir = filePath.parent_path();
        if (!parentDir.empty()) {
            std::error_code ec;
            std::filesystem::create_directories(parentDir, ec);
            if (ec) {
                throw std::runtime_error("Failed to create output directory: " +
                                       parentDir.string() + " - " + ec.message());
            }
        }

        std::ofstream file(filePath, std::ios::binary | std::ios::trunc);
        if (!file) {
            throw std::runtime_error("Cannot open file for writing: " + filePath.string());
        }

        file.write(reinterpret_cast<const char*>(data.data()), data.size());
        if (!file) {
            throw std::runtime_error("Failed to write data to file: " + filePath.string());
        }
    }


    bool looksLikeZlib(const std::vector<unsigned char>& v)
    {
        if (v.size() < 2)
        {
            return false;
        }
        const uint8_t cmf = v[0], flg = v[1];
        if (cmf != 0x78) return false;
        // zlib header constraint: (cmf << 8 | flg) % 31 == 0
        return (((static_cast<unsigned>(cmf) << 8) | flg) % 31) == 0;
    }
    bool hasMagicZip(const std::vector<unsigned char>& v)
    {
        return v.size() >= 4 && v[0]==0x50 && v[1]==0x4B && v[2]==0x03 && v[3]==0x04; // "PK\x03\x04"
    }
    bool hasMagicPNG(const std::vector<unsigned char>& v)
    {
        static const unsigned char sig[8] = {0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A};
        return v.size() >= 8 && std::equal(std::begin(sig), std::end(sig), v.begin());    
    }
    bool hasMagicWEBP(const std::vector<unsigned char>& v) 
    {
        return v.size() >= 12 && v[0]=='R' && v[1]=='I' && v[2]=='F' && v[3]=='F'
           && v[8]=='W' && v[9]=='E' && v[10]=='B' && v[11]=='P';
    }
    std::pair<const unsigned char*, std::size_t> alignBlockCipherPayload(const std::vector<unsigned char>& fileBytes, std::size_t dataOffset)
    {

        if (fileBytes.size() < dataOffset + 16) 
        {
        throw std::runtime_error("cipher too small");
        }
        std::size_t len = fileBytes.size() - dataOffset;

        // Common case: trailing 10-byte MAC → trim if that fixes alignment
        if ((len % 16) != 0 && len >= 10 && ((len - 10) % 16) == 0) 
        {
            len -= 10;
        }

        if ((len % 16) != 0)
        {
            // As a last resort, try trimming up to 15 bytes (defensive).
            // If this ever triggers, the header offsets are probably wrong.
            for (std::size_t t = 1; t <= 15 && len > t; ++t)
            {
                if (((len - t) % 16) == 0)
                {
                    len -= t; break;
                }
            }
        }

        if ((len % 16) != 0) 
        {
            throw std::runtime_error("ciphertext not 16-byte aligned; wrong offsets?");
        }

        return { fileBytes.data() + dataOffset, len };
    }


    std::string base64urlTobase64(const std::string& urlsafe)
    {
        std::string temp = urlsafe;
        for (char& c : temp) if (c == '-') c = '+';
        for (char& c : temp) if (c == '_') c = '/';
        while (temp.size() % 4) temp.push_back('=');
        return temp;
    }

    std::filesystem::file_time_type toFileTime(const std::chrono::system_clock::time_point tp)
    {
        using namespace std::chrono;
        const auto sys_now  = system_clock::now();
        const auto file_now = std::filesystem::file_time_type::clock::now();
        return file_now + (tp - sys_now);
    }

    bool ctEq(const unsigned char* a, const unsigned char* b, size_t n)
    {
        unsigned char d = 0;
        for (size_t i = 0; i < n; i++)
        {
            d |= a[i] ^ b[i];
        }
        return d == 0;
    }


    nlohmann::json decryptMetadata(const std::string& encodedB64,
                                         const Key15& key15)
    {
        if (encodedB64.empty())
            throw std::runtime_error("mcrypt1 metadata: empty input");

        std::vector<unsigned char> blob;
        try
        {
            blob = base64decode(encodedB64);
        } catch (...)
        {
            // tolerate url-safe strings as fallback
            const auto b64std = base64urlTobase64(encodedB64);
            blob = base64decode(b64std);
        }
        // minimal structure
        if (blob.size() < MetadataConstants::MIN_BLOB_SIZE)
        {
            throw std::runtime_error("mcrypt1 metadata: blob too short");
        }

        // Layout: [iv_size(1)] [IV(16)] [mac_size(1)] [MAC(32)] [CIPHERTEXT...]
        size_t offset = 0;
        const uint8_t ivSize = blob[offset++]; // 0

        if (ivSize != MetadataConstants::IV_LEN)
        {
            throw std::runtime_error("IV size != 16");
        }
        if (offset + MetadataConstants::IV_LEN > blob.size())
        {
            throw std::runtime_error("Truncated IV");
        }
        std::vector<unsigned char> iv(blob.begin() + offset, blob.begin() + offset + 16);
        offset += MetadataConstants::IV_LEN ;

        const uint8_t macSize = blob[offset++];                // 17
        if (macSize != MetadataConstants::MAC_LEN)
        {
            throw std::runtime_error("MAC size != 32");
        }
        if (offset + MetadataConstants::MAC_LEN > blob.size())
        {
            throw std::runtime_error("Truncated MAC");
        }
        const unsigned char* mac = blob.data() + offset;        // 18..49
        offset += MetadataConstants::MAC_LEN;

        if (offset >= blob.size())
        {
            throw std::runtime_error("Missing encrypted metadata");
        }
        std::vector<unsigned char> enc(blob.begin() + offset, blob.end());

        // --- HMAC(AuthKey, IV || CIPHERTEXT)
        const auto authArr = key15.getMetadataAuthentication(); // 32B
        std::array<unsigned char, 32> mac_calc = hmacSha256(authArr.data(), authArr.size(),
                                                             iv.data(), iv.size(),
                                                             enc.data(), enc.size());
        if (!ctEq(mac, mac_calc.data(), MetadataConstants::MAC_LEN))
            throw std::runtime_error("Metadata MAC mismatch");

        // --- AES-256-CBC decrypt w/ PKCS#7 padding
        const auto encArr = key15.getMetadataEncryption(); // 32B
        const std::vector<unsigned char> key(encArr.begin(), encArr.end());
        std::vector<unsigned char> pt = aesCbcDecrypt(enc, key, iv); // this EVP version handles PKCS7

        // Parse JSON
        const std::string js(pt.begin(), pt.end());
        try
        {
            return nlohmann::json::parse(js);
        }
        catch (const nlohmann::json::parse_error& e)
        {
            // helpful preview
            std::string preview = js.substr(0, std::min<size_t>(32, js.size()));
            for (auto& c : preview)
            {
                if (static_cast<unsigned char>(c) < 32)
                {
                    c='.';
                }
            }
            throw std::runtime_error(std::string("Failed to parse metadata JSON: ") +
                                     e.what() + " | preview=\"" + preview + "\"");
        }
    }


    std::array<unsigned char, 32> hmacSha256(const unsigned char* key, size_t keyLen,
                                              const unsigned char* d1, size_t l1,
                                              const unsigned char* d2, size_t l2,
                                              const unsigned char* d3, size_t l3)
    {

        std::array<unsigned char, 32> out{};
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
        if (!mac)
        {
            throw std::runtime_error("EVP_MAC_fetch(HMAC) failed");
        }

        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (!ctx)
        {
            throw std::runtime_error("EVP_MAC_CTX_new failed");
        }

        // Select SHA-256 for the HMAC
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_ALG_PARAM_DIGEST,
            const_cast<char*>("SHA256"),
            0);
        params[1] = OSSL_PARAM_END;

        if (EVP_MAC_init(ctx, key, keyLen, params) != 1)
            {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("EVP_MAC_init failed");
        }

        if (d1 && l1 && EVP_MAC_update(ctx, d1, l1) != 1)
        {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("EVP_MAC_update d1 failed");
        }
        if (d2 && l2 && EVP_MAC_update(ctx, d2, l2) != 1)
        {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("EVP_MAC_update d2 failed");
        }
        if (d3 && l3 && EVP_MAC_update(ctx, d3, l3) != 1)
        {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("EVP_MAC_update d3 failed");
        }

        size_t outLen = out.size();
        if (EVP_MAC_final(ctx, out.data(), &outLen, out.size()) != 1)
        {
            EVP_MAC_CTX_free(ctx);
            throw std::runtime_error("EVP_MAC_final failed");
        }
        EVP_MAC_CTX_free(ctx);
        if (outLen != out.size())
        {
            throw std::runtime_error("Unexpected HMAC length");
        }
        return out;
    }

    std::vector<unsigned char> hmacEncryptionloop(const std::array<unsigned char, Key15::KEY_SIZE>& root,
                                                    const std::vector<unsigned char>& message,
                                                    size_t output_bytes)
    {
        if (output_bytes == 0)
        {
            return {};
        }
        // privatekey = HMAC(ZERO32, root)
        constexpr unsigned char ZERO32BYTES[32] = {0};
        auto privateKey = hmacSha256(ZERO32BYTES, sizeof(ZERO32BYTES), root.data(), root.size()); // 32B

        std::vector<unsigned char> out;
        out.reserve(output_bytes);
        std::array<unsigned char, 32> data_prev{}; // empty on first iteration
        size_t produced = 0;

        for (uint8_t i = 1; produced < output_bytes; ++i)
        {
            std::array<unsigned char, 32> digest =
                hmacSha256(privateKey.data(), privateKey.size(),
                            (produced==0) ? nullptr : data_prev.data(), (produced==0)?0:32,
                            message.data(), message.size(),
                            &i, 1);
            size_t take = std::min<size_t>(32, output_bytes - produced);
            out.insert(out.end(), digest.begin(), digest.begin() + take);
            data_prev = digest;
            produced += take;
        }
        return out;
    }

} // namespace decryptorUtils
