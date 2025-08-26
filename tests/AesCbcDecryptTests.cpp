#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <random>
#include <memory>

#include "utils.h"

class AesCbcDecryptTest : public ::testing::Test {
protected:
    void SetUp() override {
    }

    void TearDown() override {}

    // Helper function to create a vector from string
    std::vector<unsigned char> stringToVector(const std::string& str)
    {
        return std::vector<unsigned char>(str.begin(), str.end());
    }

    // Helper function to create random bytes
    std::vector<unsigned char> createRandomBytes(size_t length)
    {
        std::vector<unsigned char> result(length);
        if (RAND_bytes(result.data(), static_cast<int>(length)) != 1) {
            // Fallback to pseudo-random if OpenSSL random fails
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, 255);
            for (size_t i = 0; i < length; ++i) {
                result[i] = static_cast<unsigned char>(dis(gen));
            }
        }
        return result;
    }

    // Helper function to encrypt data for testing decryption
    std::vector<unsigned char> aesCbcEncrypt(const std::vector<unsigned char>& plaintext,
                                           const std::vector<unsigned char>& key,
                                           const std::vector<unsigned char>& iv) {
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
            ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);

        if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            throw std::runtime_error("Encryption initialization failed");
        }

        std::vector<unsigned char> ciphertext(plaintext.size() + 16);
        int len = 0;
        int ciphertextLen = 0;

        if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(),
                             static_cast<int>(plaintext.size())) != 1) {
            throw std::runtime_error("Encryption failed");
        }
        ciphertextLen = len;

        if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
            throw std::runtime_error("Encryption finalization failed");
        }
        ciphertextLen += len;

        ciphertext.resize(ciphertextLen);
        return ciphertext;
    }

    // Standard test vectors
    std::vector<unsigned char> getTestKey() {
        return createRandomBytes(32);
    }

    std::vector<unsigned char> getTestIv() {
        return createRandomBytes(16);
    }
};

// Test successful decryption with valid inputs
TEST_F(AesCbcDecryptTest, decryptsValidCiphertext)
{
    auto key = getTestKey();
    auto iv = getTestIv();
    auto originalPlaintext = stringToVector("Hello, World! This is a test message.");

    // Encrypt the plaintext to get valid ciphertext
    auto ciphertext = aesCbcEncrypt(originalPlaintext, key, iv);

    // Decrypt and verify
    auto decryptedPlaintext = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);

    EXPECT_EQ(originalPlaintext, decryptedPlaintext);
}

// Test with empty ciphertext - should throw
TEST_F(AesCbcDecryptTest, throwsOnEmptyCiphertext) {
    std::vector<unsigned char> emptyCiphertext;
    auto key = getTestKey();
    auto iv = getTestIv();

    EXPECT_THROW(decryptorUtils::aesCbcDecrypt(emptyCiphertext, key, iv), std::runtime_error);
}

// Test with wrong key size - should throw
TEST_F(AesCbcDecryptTest, throwsOnInvalidKeySize) {
    auto ciphertext = createRandomBytes(16); // Valid block size
    auto iv = getTestIv();

    // Test various invalid key sizes
    std::vector<size_t> invalidKeySizes = {0, 15, 16, 24, 31, 33, 64};

    for (size_t keySize : invalidKeySizes) {
        auto invalidKey = createRandomBytes(keySize);
        EXPECT_THROW(decryptorUtils::aesCbcDecrypt(ciphertext, invalidKey, iv), std::runtime_error)
            << "Failed for key size: " << keySize;
    }
}

// Test with wrong IV size - should throw
TEST_F(AesCbcDecryptTest, throwsOnInvalidIvSize) {
    auto ciphertext = createRandomBytes(16); // Valid block size
    auto key = getTestKey();

    // Test various invalid IV sizes
    std::vector<size_t> invalidIvSizes = {0, 8, 15, 17, 32};

    for (size_t ivSize : invalidIvSizes) {
        auto invalidIv = createRandomBytes(ivSize);
        EXPECT_THROW(decryptorUtils::aesCbcDecrypt(ciphertext, key, invalidIv), std::runtime_error)
            << "Failed for IV size: " << ivSize;
    }
}

// Test with ciphertext not multiple of 16 bytes - should throw
TEST_F(AesCbcDecryptTest, throwsOnInvalidCiphertextLength) {
    auto key = getTestKey();
    auto iv = getTestIv();

    std::vector<size_t> invalidLengths = {1, 7, 15, 17, 23, 31, 33};

    for (size_t length : invalidLengths) {
        auto invalidCiphertext = createRandomBytes(length);
        EXPECT_THROW(decryptorUtils::aesCbcDecrypt(invalidCiphertext, key, iv), std::runtime_error)
            << "Failed for ciphertext length: " << length;
    }
}

// Test with invalid padding - should throw
TEST_F(AesCbcDecryptTest, throwsOnInvalidPadding) {
    auto key = getTestKey();
    auto iv = getTestIv();

    // Create random data that's not properly encrypted (invalid padding)
    auto invalidCiphertext = createRandomBytes(32);

    EXPECT_THROW(decryptorUtils::aesCbcDecrypt(invalidCiphertext, key, iv), std::runtime_error);
}

// Test with wrong key - should throw due to padding validation
TEST_F(AesCbcDecryptTest, throwsOnWrongKey) {
    auto correctKey = getTestKey();
    auto wrongKey = getTestKey(); // Different key
    auto iv = getTestIv();
    auto plaintext = stringToVector("Test message for wrong key test");

    auto ciphertext = aesCbcEncrypt(plaintext, correctKey, iv);

    EXPECT_THROW(decryptorUtils::aesCbcDecrypt(ciphertext, wrongKey, iv), std::runtime_error);
}

// Test with wrong IV - should produce garbage but not throw
TEST_F(AesCbcDecryptTest, handlesWrongIv) {
    auto key = getTestKey();
    auto correctIv = getTestIv();
    auto wrongIv = getTestIv(); // Different IV
    auto plaintext = stringToVector("Test message for wrong IV test");

    auto ciphertext = aesCbcEncrypt(plaintext, key, correctIv);

    // Wrong IV typically produces garbage output but might not throw
    // depending on the resulting padding
    EXPECT_NO_THROW({
        try {
            auto result = decryptorUtils::aesCbcDecrypt(ciphertext, key, wrongIv);
            // If it doesn't throw, the result should be different from original
            EXPECT_NE(plaintext, result);
        } catch (const std::runtime_error&) {
            // It's also valid to throw due to invalid padding
            SUCCEED() << "Function correctly threw on invalid padding from wrong IV";
        }
    });
}

// Test with various block sizes
TEST_F(AesCbcDecryptTest, handlesMultipleBlockSizes) {
    auto key = getTestKey();
    auto iv = getTestIv();

    std::vector<size_t> blockCounts = {1, 2, 4, 8, 16, 32};

    for (size_t blocks : blockCounts) {
        size_t plaintextSize = blocks * 16 - 1; // -1 to ensure padding is added
        auto plaintext = createRandomBytes(plaintextSize);

        auto ciphertext = aesCbcEncrypt(plaintext, key, iv);
        auto decrypted = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);

        EXPECT_EQ(plaintext, decrypted) << "Failed for " << blocks << " blocks";
    }
}

// Test with different plaintext sizes to test padding
TEST_F(AesCbcDecryptTest, handlesVariousPlaintextSizes) {
    auto key = getTestKey();
    auto iv = getTestIv();

    for (size_t size = 1; size <= 64; ++size) {
        auto plaintext = createRandomBytes(size);

        auto ciphertext = aesCbcEncrypt(plaintext, key, iv);
        auto decrypted = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);

        EXPECT_EQ(plaintext, decrypted) << "Failed for plaintext size: " << size;
    }
}

// Test with binary data containing null bytes
TEST_F(AesCbcDecryptTest, handlesBinaryDataWithNullBytes) {
    auto key = getTestKey();
    auto iv = getTestIv();

    std::vector<unsigned char> binaryData = {0x00, 0x01, 0x02, 0x00, 0xFF, 0x00, 0xAB, 0xCD};

    auto ciphertext = aesCbcEncrypt(binaryData, key, iv);
    auto decrypted = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);

    EXPECT_EQ(binaryData, decrypted);
}

// Test with large data
TEST_F(AesCbcDecryptTest, handlesLargeData) {
    auto key = getTestKey();
    auto iv = getTestIv();

    size_t largeSize = 10240; // 10KB
    auto largePlaintext = createRandomBytes(largeSize);

    auto ciphertext = aesCbcEncrypt(largePlaintext, key, iv);
    auto decrypted = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);

    EXPECT_EQ(largePlaintext, decrypted);
}

// Test deterministic behavior - same inputs produce same outputs
TEST_F(AesCbcDecryptTest, producesDeterministicOutput) {
    auto key = getTestKey();
    auto iv = getTestIv();
    auto plaintext = stringToVector("Deterministic test message");

    auto ciphertext = aesCbcEncrypt(plaintext, key, iv);

    auto result1 = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);
    auto result2 = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);

    EXPECT_EQ(result1, result2);
    EXPECT_EQ(plaintext, result1);
}

// Test with edge case: exactly one block of plaintext (15 bytes + padding)
TEST_F(AesCbcDecryptTest, handlesExactlyOneBlockPadding) {
    auto key = getTestKey();
    auto iv = getTestIv();

    // 15 bytes will result in exactly one block after padding
    auto plaintext = createRandomBytes(15);

    auto ciphertext = aesCbcEncrypt(plaintext, key, iv);
    EXPECT_EQ(ciphertext.size(), 16u); // Should be exactly one block

    auto decrypted = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);
    EXPECT_EQ(plaintext, decrypted);
}

// Test with edge case: exactly block-aligned plaintext (16 bytes)
TEST_F(AesCbcDecryptTest, handlesBlockAlignedPlaintext) {
    auto key = getTestKey();
    auto iv = getTestIv();

    // 16 bytes will result in two blocks (one data + one padding block)
    auto plaintext = createRandomBytes(16);

    auto ciphertext = aesCbcEncrypt(plaintext, key, iv);
    EXPECT_EQ(ciphertext.size(), 32u); // Should be two blocks

    auto decrypted = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);
    EXPECT_EQ(plaintext, decrypted);
}

// Performance test
TEST_F(AesCbcDecryptTest, performanceTest) {
    auto key = getTestKey();
    auto iv = getTestIv();
    auto plaintext = createRandomBytes(1024); // 1KB
    auto ciphertext = aesCbcEncrypt(plaintext, key, iv);

    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
        auto result = decryptorUtils::aesCbcDecrypt(ciphertext, key, iv);
        // Prevent optimization
        volatile auto temp = result[0];
        (void)temp;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_LT(duration.count(), 5000) << "AES-CBC decryption should complete " 
                                      << iterations << " operations in reasonable time";
}
