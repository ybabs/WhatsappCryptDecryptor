#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <array>
#include <numeric>

#include "utils.h"

// --- AES-CBC (PKCS7) encrypt helper
static std::vector<unsigned char>
aesCbcEncrypt(const std::vector<unsigned char>& pt,
              const std::vector<unsigned char>& key,
              const std::vector<unsigned char>& iv)
{
    const EVP_CIPHER* cipher = nullptr;
    if (key.size() == 32 && iv.size() == 16)      cipher = EVP_aes_256_cbc();
    else if (key.size() == 16 && iv.size() == 16) cipher = EVP_aes_128_cbc();
    else throw std::runtime_error("aesCbcEncrypt: bad key/iv size");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<unsigned char> out(pt.size() + EVP_CIPHER_block_size(cipher));
    int outlen1 = 0, outlen2 = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (EVP_EncryptUpdate(ctx, out.data(), &outlen1, pt.data(), (int)pt.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    if (EVP_EncryptFinal_ex(ctx, out.data() + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx); throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    out.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

// --- HMAC-SHA256 over (IV || CIPHERTEXT)
static std::array<unsigned char, 32>
hmacSha256(const unsigned char* key, size_t keyLen,
           const std::vector<unsigned char>& iv,
           const std::vector<unsigned char>& ct)
{
    std::array<unsigned char, 32> mac{};
    unsigned int maclen = 0;
    HMAC_CTX* hctx = HMAC_CTX_new();
    if (!hctx) throw std::runtime_error("HMAC_CTX_new failed");

    if (HMAC_Init_ex(hctx, key, (int)keyLen, EVP_sha256(), nullptr) != 1 ||
        HMAC_Update(hctx, iv.data(),   (int)iv.size())                 != 1 ||
        HMAC_Update(hctx, ct.data(),   (int)ct.size())                 != 1 ||
        HMAC_Final(hctx, mac.data(), &maclen)                          != 1)
    {
        HMAC_CTX_free(hctx);
        throw std::runtime_error("HMAC calculation failed");
    }
    HMAC_CTX_free(hctx);
    if (maclen != mac.size()) throw std::runtime_error("HMAC size unexpected");
    return mac;
}


std::string createEncryptedMetadata(const nlohmann::json& jsonData, const Key15& key15)
{
    // keys (must both be 32 bytes for AES-256/HMAC-SHA256)
    const auto encArr  = key15.getMetadataEncryption();
    const auto authArr = key15.getMetadataAuthentication();
    const std::vector<unsigned char> encKey(encArr.begin(),  encArr.end());

    // deterministic IV for stable tests (00..0F)
    std::vector<unsigned char> iv(16);
    std::iota(iv.begin(), iv.end(), 0);

    // plaintext
    const std::string js = jsonData.dump();
    const std::vector<unsigned char> pt(js.begin(), js.end());

    // encrypt
    const auto ct  = aesCbcEncrypt(pt, encKey, iv);

    // mac = HMAC-SHA256(authKey, IV || CIPHERTEXT)
    const auto mac = hmacSha256(authArr.data(), authArr.size(), iv, ct);

    // assemble blob: [1][IV(16)][1][MAC(32)][CT...]
    std::vector<unsigned char> blob;
    blob.reserve(1 + iv.size() + 1 + mac.size() + ct.size());

    blob.push_back((unsigned char)iv.size());          // iv_size = 16
    blob.insert(blob.end(), iv.begin(), iv.end());     // IV
    blob.push_back((unsigned char)mac.size());         // mac_size = 32
    blob.insert(blob.end(), mac.begin(), mac.end());   // MAC
    blob.insert(blob.end(), ct.begin(), ct.end());     // ciphertext

    // base64-encode full blob
    return decryptorUtils::base64encode(blob);
}

class DecryptMetadataTest: public ::testing::Test
{
    protected:
    void SetUp () override
    {

        std::vector<char> keyBytes32 = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };

        std::vector<char> keyBytes16 = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };

        std::vector<char> invalidKeyBytes = {
    -1,  -2,  -3,  -4,  -5,  -6,  -7,  -8,
    -9, -10, -11, -12, -13, -14, -15, -16,
   -17, -18, -19, -20, -21, -22, -23, -24,
   -25, -26, -27, -28, -29, -30, -31, -32
        };

        if (Key15::KEY_SIZE == 32) {
            validKey1 = Key15(keyBytes32);
            invalidKey = Key15(invalidKeyBytes);
            // Create a second valid key by modifying the first
            keyBytes32[0] = 0x01;
            validKey2 = Key15(keyBytes32);
        } else if (Key15::KEY_SIZE == 16) {
            validKey1 = Key15(keyBytes16);
            // Create a second valid key and invalid key with correct size
            keyBytes16[0] = 0x01;
            validKey2 = Key15(keyBytes16);
            std::vector<char> invalidKeyBytes16 = 
            {
                -1,  -2,  -3,  -4,
                -5,  -6,  -7,  -8,
                -9, -10, -11, -12,
            -13, -14, -15, -16
            };
            invalidKey = Key15(invalidKeyBytes16);
        } else {
            // Handle other key sizes by creating vectors of the correct size
            std::vector<char> correctSizeKey(Key15::KEY_SIZE, 0x00);
            std::vector<char> correctSizeKey2(Key15::KEY_SIZE, 0x01);
            std::vector<char> correctSizeInvalidKey(Key15::KEY_SIZE, 0xff);

            validKey1 = Key15(correctSizeKey);
            validKey2 = Key15(correctSizeKey2);
            invalidKey = Key15(correctSizeInvalidKey);
        }

        simpleJsonData = nlohmann::json{
                {"key1", "value1"},
                {"key2", 42},
                {"key3", true}
        };

        complexJsonData = nlohmann::json{
                {"metadata", {
                    {"version", "1.0"},
                    {"created", "2024-01-01T00:00:00Z"},
                    {"user", {
                        {"id", 12345},
                        {"name", "Test User"},
                        {"roles", {"admin", "user"}}
                    }},
                    {"settings", {
                        {"theme", "dark"},
                        {"language", "en"},
                        {"notifications", true}
                    }}
                }},
                {"data", {
                    {"items", {1, 2, 3, 4, 5}},
                    {"flags", {true, false, true}}
                }}
        };

        emptyJsonData = nlohmann::json{};

        largeJsonData = nlohmann::json{};
        for (int i = 0; i < 1000; ++i) {
            largeJsonData["item_" + std::to_string(i)] = {
                {"id", i},
                {"name", "Item " + std::to_string(i)},
                {"value", i * 3.14159},
                {"active", i % 2 == 0}
            };
        }

    }


    Key15 validKey1, validKey2, invalidKey;
    nlohmann::json simpleJsonData, complexJsonData, emptyJsonData, largeJsonData;
    
};

TEST_F(DecryptMetadataTest, successfulDecryptionSimpleJson) {
    std::string encryptedMetadata = createEncryptedMetadata(simpleJsonData, validKey1);
    auto decryptedJson = decryptorUtils::decryptMetadata(encryptedMetadata, validKey1);

    EXPECT_EQ(decryptedJson, simpleJsonData);
}

TEST_F(DecryptMetadataTest, successfulDecryptionComplexJson) {
    std::string encryptedMetadata = createEncryptedMetadata(complexJsonData, validKey1);

    auto decryptedJson = decryptorUtils::decryptMetadata(encryptedMetadata, validKey1);

    EXPECT_EQ(decryptedJson, complexJsonData);
}

TEST_F(DecryptMetadataTest, successfulDecryptionEmptyJson) {
    std::string encryptedMetadata = createEncryptedMetadata(emptyJsonData, validKey1);
    auto decryptedJson = decryptorUtils::decryptMetadata(encryptedMetadata, validKey1);
    EXPECT_EQ(decryptedJson, emptyJsonData);
}

TEST_F(DecryptMetadataTest, successfulDecryptionLargeJson) {
    std::string encryptedMetadata = createEncryptedMetadata(largeJsonData, validKey1);

    auto decryptedJson = decryptorUtils::decryptMetadata(encryptedMetadata, validKey1);

    EXPECT_EQ(decryptedJson, largeJsonData);
}

TEST_F(DecryptMetadataTest, successfulDecryptionDifferentKeys) {
    // Test with first valid key
    std::string encryptedMetadata1 = createEncryptedMetadata(simpleJsonData, validKey1);
    auto decryptedJson1 = decryptorUtils::decryptMetadata(encryptedMetadata1, validKey1);
    EXPECT_EQ(decryptedJson1, simpleJsonData);

    // Test with second valid key
    std::string encryptedMetadata2 = createEncryptedMetadata(simpleJsonData, validKey2);
    auto decryptedJson2 = decryptorUtils::decryptMetadata(encryptedMetadata2, validKey2);
    EXPECT_EQ(decryptedJson2, simpleJsonData);
}

TEST_F(DecryptMetadataTest, successfulDecryptionSpecialCharacters) {
    nlohmann::json specialCharsJson = nlohmann::json{
            {"unicode", "こんにちは世界"},
            {"symbols", "!@#$%^&*()_+-=[]{}|;':\",./<>?"},
            {"newlines", "line1\nline2\r\nline3"},
            {"tabs", "col1\tcol2\tcol3"},
            {"quotes", "He said \"Hello\" to me"},
            {"backslashes", "C:\\Users\\test\\file.txt"}
    };

    std::string encryptedMetadata = createEncryptedMetadata(specialCharsJson, validKey1);
    auto decryptedJson = decryptorUtils::decryptMetadata(encryptedMetadata, validKey1);

    EXPECT_EQ(decryptedJson, specialCharsJson);
}

TEST_F(DecryptMetadataTest, successfulDecryptionVariousDataTypes) {
    nlohmann::json dataTypesJson = nlohmann::json{
            {"string", "test"},
            {"integer", 42},
            {"float", 3.14159},
            {"boolean_true", true},
            {"boolean_false", false},
            {"null_value", nullptr},
            {"array", {1, 2, 3, "four", true}},
            {"nested_object", {
                {"inner_string", "inner"},
                {"inner_number", 999}
            }}
    };

    std::string encryptedMetadata = createEncryptedMetadata(dataTypesJson, validKey1);
    auto decryptedJson = decryptorUtils::decryptMetadata(encryptedMetadata, validKey1);

    EXPECT_EQ(decryptedJson, dataTypesJson);
}

TEST_F(DecryptMetadataTest, emptyInputString) {
    EXPECT_THROW(
        decryptorUtils::decryptMetadata("", validKey1),
        std::runtime_error
    );
}

TEST_F(DecryptMetadataTest, invalidBase64Input) {
    std::string invalidBase64 = "This is not base64!@#$%";

    EXPECT_THROW(
        decryptorUtils::decryptMetadata(invalidBase64, validKey1),
        std::runtime_error
    );
}

TEST_F(DecryptMetadataTest, validBase64InvalidEncryptedData) {
    // Create valid base64 that doesn't represent valid encrypted metadata
    std::string validBase64InvalidData = "SGVsbG8gV29ybGQ="; // "Hello World" in base64

    EXPECT_THROW(
        decryptorUtils::decryptMetadata(validBase64InvalidData, validKey1),
        std::runtime_error
    );
}

TEST_F(DecryptMetadataTest, wrongDecryptionKey) {
    std::string encryptedMetadata = createEncryptedMetadata(simpleJsonData, validKey1);

    EXPECT_THROW(
        decryptorUtils::decryptMetadata(encryptedMetadata, invalidKey),
        std::runtime_error
    );
}

TEST_F(DecryptMetadataTest, corruptedEncryptedData) {
    std::string encryptedMetadata = createEncryptedMetadata(simpleJsonData, validKey1);

    // Corrupt the base64 string (change a character)
    if (!encryptedMetadata.empty()) {
        encryptedMetadata[0] = (encryptedMetadata[0] == 'A') ? 'B' : 'A';
    }

    EXPECT_THROW(
        decryptorUtils::decryptMetadata(encryptedMetadata, validKey1),
        std::runtime_error
    );
}

