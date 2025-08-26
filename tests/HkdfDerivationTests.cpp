#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <random>

#include "utils.h"


class HkdfDeriveTest : public ::testing::Test {
protected:
    void SetUp() override 
    {
    }
    
    void TearDown() override {}
    
    // Helper function to create test vectors
    std::vector<unsigned char> createTestVector(const std::string& data) 
    {
        return std::vector<unsigned char>(data.begin(), data.end());
    }
    
    // Helper function to create random bytes
    std::vector<unsigned char> createRandomBytes(size_t length) 
    {
        std::vector<unsigned char> result(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < length; ++i) {
            result[i] = static_cast<unsigned char>(dis(gen));
        }
        return result;
    }
};

// Test basic functionality with valid inputs
TEST_F(HkdfDeriveTest, derivesKeyWithValidInputs) {
    auto salt = createTestVector("salt");
    auto ikm = createTestVector("input key material");
    std::string info = "test info";
    size_t outputLength = 32;
    
    auto result = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
    
    EXPECT_EQ(result.size(), outputLength);
    EXPECT_FALSE(std::all_of(result.begin(), result.end(), [](unsigned char c) { return c == 0; }));
}


TEST_F(HkdfDeriveTest, throwsOnEmptySalt) {
    std::vector<unsigned char> emptySalt;
    auto ikm = createTestVector("input key material");
    std::string info = "test info";
    size_t outputLength = 32;
    
    EXPECT_THROW(decryptorUtils::hkdfDerive(emptySalt, ikm, info, outputLength), std::runtime_error);
}

TEST_F(HkdfDeriveTest, throwsOnEmptyInputKeyMaterial) {
    auto salt = createTestVector("salt");
    std::vector<unsigned char> emptyIkm;
    std::string info = "test info";
    size_t outputLength = 32;
    
    EXPECT_THROW(decryptorUtils::hkdfDerive(salt, emptyIkm, info, outputLength), std::runtime_error);
}

TEST_F(HkdfDeriveTest, throwsOnZeroOutputLength) {
    auto salt = createTestVector("salt");
    auto ikm = createTestVector("input key material");
    std::string info = "test info";
    size_t outputLength = 0;
    
    EXPECT_THROW(decryptorUtils::hkdfDerive(salt, ikm, info, outputLength), std::runtime_error);
}
TEST_F(HkdfDeriveTest, throwsOnTooLargeOutputLength) 
{
    auto salt = createTestVector("salt");
    auto ikm = createTestVector("input key material");
    std::string info = "test info";
    size_t outputLength = 255 * 32 + 1; // Exceeds RFC 5869 limit
    
    EXPECT_THROW(decryptorUtils::hkdfDerive(salt, ikm, info, outputLength), std::runtime_error);
}

TEST_F(HkdfDeriveTest, handlesMaximumValidOutputLength) 
{
    auto salt = createTestVector("salt");
    auto ikm = createTestVector("input key material");
    std::string info = "test info";
    size_t outputLength = 255 * 32; // Maximum RFC 5869 limit
    
    EXPECT_NO_THROW({
        auto result = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
        EXPECT_EQ(result.size(), outputLength);
    });
}

// Test with empty info parameter
TEST_F(HkdfDeriveTest, handlesEmptyInfo) 
{
    auto salt = createTestVector("salt");
    auto ikm = createTestVector("input key material");
    std::string info = "";
    size_t outputLength = 32;
    
    EXPECT_NO_THROW({
        auto result = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
        EXPECT_EQ(result.size(), outputLength);
    });
}

TEST_F(HkdfDeriveTest, producesDeterministicOutput) 
{
    auto salt = createTestVector("test salt");
    auto ikm = createTestVector("test input key material");
    std::string info = "test info";
    size_t outputLength = 64;
    
    auto result1 = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
    auto result2 = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
    
    EXPECT_EQ(result1, result2);
}

TEST_F(HkdfDeriveTest, differentSaltsProduceDifferentOutputs) 
{
    auto salt1 = createTestVector("salt1");
    auto salt2 = createTestVector("salt2");
    auto ikm = createTestVector("input key material");
    std::string info = "test info";
    size_t outputLength = 32;
    
    auto result1 = decryptorUtils::hkdfDerive(salt1, ikm, info, outputLength);
    auto result2 = decryptorUtils::hkdfDerive(salt2, ikm, info, outputLength);
    
    EXPECT_NE(result1, result2);
}

TEST_F(HkdfDeriveTest, differentIkmProducesDifferentOutputs) 
{
    auto salt = createTestVector("salt");
    auto ikm1 = createTestVector("input key material 1");
    auto ikm2 = createTestVector("input key material 2");
    std::string info = "test info";
    size_t outputLength = 32;
    
    auto result1 = decryptorUtils::hkdfDerive(salt, ikm1, info, outputLength);
    auto result2 = decryptorUtils::hkdfDerive(salt, ikm2, info, outputLength);
    
    EXPECT_NE(result1, result2);
}

TEST_F(HkdfDeriveTest, differentInfoProducesDifferentOutputs) 
{
    auto salt = createTestVector("salt");
    auto ikm = createTestVector("input key material");
    std::string info1 = "test info 1";
    std::string info2 = "test info 2";
    size_t outputLength = 32;
    
    auto result1 = decryptorUtils::hkdfDerive(salt, ikm, info1, outputLength);
    auto result2 = decryptorUtils::hkdfDerive(salt, ikm, info2, outputLength);
    
    EXPECT_NE(result1, result2);
}

TEST_F(HkdfDeriveTest, handlesVariousOutputLengths) 
{
    auto salt = createTestVector("salt");
    auto ikm = createTestVector("input key material");
    std::string info = "test info";
    
    std::vector<size_t> lengths = {1, 16, 32, 64, 128, 256, 1024};
    
    for (size_t length : lengths) {
        EXPECT_NO_THROW({
            auto result = decryptorUtils::hkdfDerive(salt, ikm, info, length);
            EXPECT_EQ(result.size(), length);
        }) << "Failed for output length: " << length;
    }
}

// Test with binary salt and IKM
TEST_F(HkdfDeriveTest, handlesBinaryData) 
{
    auto salt = createRandomBytes(16);
    auto ikm = createRandomBytes(32);
    std::string info = "binary test";
    size_t outputLength = 48;
    
    EXPECT_NO_THROW({
        auto result = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
        EXPECT_EQ(result.size(), outputLength);
    });
}

// Test with large salt and IKM
TEST_F(HkdfDeriveTest, handlesLargeInputs) 
{
    auto salt = createRandomBytes(1024);
    auto ikm = createRandomBytes(2048);
    std::string info = "large input test";
    size_t outputLength = 64;
    
    EXPECT_NO_THROW({
        auto result = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
        EXPECT_EQ(result.size(), outputLength);
    });
}

TEST_F(HkdfDeriveTest, handlesSpecialCharactersInInfo) 
{
    auto salt = createTestVector("salt");
    auto ikm = createTestVector("input key material");
    std::string info = "test\x00\xff\n\r\t info with special chars";
    size_t outputLength = 32;
    
    EXPECT_NO_THROW({
        auto result = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
        EXPECT_EQ(result.size(), outputLength);
    });
}

TEST_F(HkdfDeriveTest, outputAppearsRandom) 
{
    auto salt = createTestVector("entropy test salt");
    auto ikm = createTestVector("entropy test ikm");
    std::string info = "entropy test";
    size_t outputLength = 256;
    
    auto result = decryptorUtils::hkdfDerive(salt, ikm, info, outputLength);
    
    // Count unique bytes
    std::set<unsigned char> uniqueBytes(result.begin(), result.end());
    
    // For 256 bytes of good random data, we expect reasonable diversity
    EXPECT_GT(uniqueBytes.size(), 50) << "Output doesn't appear sufficiently random";
    
    // Check that not all bytes are the same
    EXPECT_FALSE(std::all_of(result.begin(), result.end(), 
                            [&result](unsigned char c) { return c == result[0]; }));
}