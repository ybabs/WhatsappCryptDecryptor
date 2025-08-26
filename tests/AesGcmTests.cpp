//
// Created by daniel on 7/25/25.
//
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <vector>
#include <string>
#include <stdexcept>
#include "utils.h"

class AESGCMDecryptTest: public ::testing::Test
{
protected:
    void SetUp() override
    {
        key128 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        key192 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

        key256 = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

        iv12 = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab};
        iv16 = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
                 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};

        aad = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
    }

    std::vector<unsigned char> key128;
    std::vector<unsigned char> key192;
    std::vector<unsigned char> key256;
    std::vector<unsigned char> iv12;
    std::vector<unsigned char> iv16;
    std::vector<unsigned char> aad;
    std::vector<unsigned char> plaintext;

};

TEST_F(AESGCMDecryptTest, SuccessfultDecryption_AES128)
{
    auto cipherText = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv12, aad, 16);
    auto decrypted = decryptorUtils::aesGcmDecrypt(cipherText, key128, iv12, aad, 16);

    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(AESGCMDecryptTest, SuccessfulDecryption_AES192)
{
    auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key192, iv12, aad, 16);
    auto decrypted = decryptorUtils::aesGcmDecrypt(ciphertext, key192, iv12, aad, 16);
    EXPECT_EQ(decrypted, plaintext);
}

// Test successful decryption with AES-256
TEST_F(AESGCMDecryptTest, SuccessfulDecryption_AES256)
{
    auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key256, iv12, aad, 16);
    auto decrypted = decryptorUtils::aesGcmDecrypt(ciphertext, key256, iv12, aad, 16);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(AESGCMDecryptTest, DifferentTagLengths)
{
    for (size_t tagLen = 12; tagLen <= 16; ++tagLen)
        {
        auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv12, aad, tagLen);
        auto decrypted = decryptorUtils::aesGcmDecrypt(ciphertext, key128, iv12, aad, tagLen);
        EXPECT_EQ(decrypted, plaintext);
    }
}
TEST_F(AESGCMDecryptTest, DifferentIVLengths)
{
    std::vector<unsigned char> iv1 = {0xa0};
    std::vector<unsigned char> iv8 = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7};

    auto ciphertext1 = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv1, aad, 16);
    auto decrypted1 = decryptorUtils::aesGcmDecrypt(ciphertext1, key128, iv1, aad, 16);
    EXPECT_EQ(decrypted1, plaintext);

    auto ciphertext8 = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv8, aad, 16);
    auto decrypted8 = decryptorUtils::aesGcmDecrypt(ciphertext8, key128, iv8, aad, 16);
    EXPECT_EQ(decrypted8, plaintext);

    auto ciphertext16 = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv16, aad, 16);
    auto decrypted16 = decryptorUtils::aesGcmDecrypt(ciphertext16, key128, iv16, aad, 16);
    EXPECT_EQ(decrypted16, plaintext);
}

TEST_F(AESGCMDecryptTest, NoAAD) {
    std::vector<unsigned char> emptyAad;
    auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv12, emptyAad, 16);
    auto decrypted = decryptorUtils::aesGcmDecrypt(ciphertext, key128, iv12, emptyAad, 16);
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(AESGCMDecryptTest, EmptyPlaintext) {
    std::vector<unsigned char> emptyPlaintext;
    auto ciphertext = decryptorUtils::aesGcmEncrypt(emptyPlaintext, key128, iv12, aad, 16);
    auto decrypted = decryptorUtils::aesGcmDecrypt(ciphertext, key128, iv12, aad, 16);
    EXPECT_EQ(decrypted, emptyPlaintext);
}

TEST_F(AESGCMDecryptTest, LargePlaintext) {
    std::vector<unsigned char> largePlaintext(10000, 0x42);
    auto ciphertext = decryptorUtils::aesGcmEncrypt(largePlaintext, key256, iv12, aad, 16);
    auto decrypted = decryptorUtils::aesGcmDecrypt(ciphertext, key256, iv12, aad, 16);
    EXPECT_EQ(decrypted, largePlaintext);
}

TEST_F(AESGCMDecryptTest, InvalidKeySize) {
    std::vector<unsigned char> invalidKey15(15, 0x00);
    std::vector<unsigned char> invalidKey17(17, 0x00);
    std::vector<unsigned char> invalidKey33(33, 0x00);
    std::vector<unsigned char> dummyCipherText(32, 0x00);

    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(dummyCipherText, invalidKey15, iv12, aad, 16), std::runtime_error);
    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(dummyCipherText, invalidKey17, iv12, aad, 16), std::runtime_error);
    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(dummyCipherText, invalidKey33, iv12, aad, 16), std::runtime_error);
}

TEST_F(AESGCMDecryptTest, InvalidIVSize) {
    std::vector<unsigned char> emptyIv;
    std::vector<unsigned char> tooLongIv(17, 0xa0);
    std::vector<unsigned char> dummyCiphertext(32, 0x00);

    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(dummyCiphertext, key128, emptyIv, aad, 16), std::runtime_error);
    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(dummyCiphertext, key128, tooLongIv, aad, 16), std::runtime_error);
}

TEST_F(AESGCMDecryptTest, InvalidTagLength) {
    std::vector<unsigned char> dummyCiphertext(32, 0x00);

    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(dummyCiphertext, key128, iv12, aad, 11), std::runtime_error);
    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(dummyCiphertext, key128, iv12, aad, 17), std::runtime_error);
}


TEST_F(AESGCMDecryptTest, CiphertextTooShort) {
    std::vector<unsigned char> short_ciphertext(15, 0x00); // Less than tag length of 16

    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(short_ciphertext, key128, iv12, aad, 16), std::runtime_error);
}


TEST_F(AESGCMDecryptTest, WrongKey) {
    auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv12, aad, 16);
    std::vector<unsigned char> wrongKey(16, 0xff);

    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(ciphertext, wrongKey, iv12, aad, 16), std::runtime_error);
}

TEST_F(AESGCMDecryptTest, WrongIV) {
    auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv12, aad, 16);
    std::vector<unsigned char> wrongiv(12, 0xff);
    
    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(ciphertext, key128, wrongiv, aad, 16), std::runtime_error);
}

TEST_F(AESGCMDecryptTest, WrongAAD) {
    auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv12, aad, 16);
    std::vector<unsigned char> wrongAad = {0x11, 0x22, 0x33, 0x44};
    
    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(ciphertext, key128, iv12, wrongAad, 16), std::runtime_error);
}

TEST_F(AESGCMDecryptTest, CorruptedCiphertext) {
    auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv12, aad, 16);
    
    // Corrupt the ciphertext (not the tag)
    if (ciphertext.size() > 16) {
        ciphertext[0] ^= 0x01;
        EXPECT_THROW(decryptorUtils::aesGcmDecrypt(ciphertext, key128, iv12, aad, 16), std::runtime_error);
    }
}


TEST_F(AESGCMDecryptTest, CorruptedTag) {
    auto ciphertext = decryptorUtils::aesGcmEncrypt(plaintext, key128, iv12, aad, 16);
    
    // Corrupt the last byte (part of the tag)
    ciphertext.back() ^= 0x01;
    EXPECT_THROW(decryptorUtils::aesGcmDecrypt(ciphertext, key128, iv12, aad, 16), std::runtime_error);
}

// Performance test (optional)
TEST_F(AESGCMDecryptTest, PerformanceTest) {
    std::vector<unsigned char> largeData(1024 * 1024, 0x42); // 1MB
    auto ciphertext = decryptorUtils::aesGcmEncrypt(largeData, key256, iv12, aad, 16);
    
    auto start = std::chrono::high_resolution_clock::now();
    auto decrypted = decryptorUtils::aesGcmDecrypt(ciphertext, key256, iv12, aad, 16);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Decrypted 1MB in " << duration.count() << " ms" << std::endl;
    
    EXPECT_EQ(decrypted, largeData);
}
