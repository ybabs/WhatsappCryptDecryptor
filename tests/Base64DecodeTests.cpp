#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <vector>
#include <string>
#include <stdexcept>


#include "utils.h"

class Base64DecodeTest : public ::testing::Test {
protected:
    void SetUp() override {
        
        helloWorld = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64}; // "Hello World"
        singleByte = {0x41}; // "A"
        twoBytes = {0x41, 0x42}; // "AB"
        threeBytes = {0x41, 0x42, 0x43}; // "ABC"
        fourBytes = {0x41, 0x42, 0x43, 0x44}; // "ABCD"
        binaryData = {0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC};
        
        largeData.resize(10000);
        for (size_t i = 0; i < largeData.size(); ++i) {
            largeData[i] = static_cast<unsigned char>(i % 256);
        }
    }

    std::vector<unsigned char> helloWorld, singleByte, twoBytes, threeBytes, fourBytes;
    std::vector<unsigned char> binaryData, largeData;
};


TEST_F(Base64DecodeTest, KnownVectors) {
    // Test cases with known base64 encodings
    EXPECT_EQ(decryptorUtils::base64decode("QQ=="), std::vector<unsigned char>({0x41})); // "A"
    EXPECT_EQ(decryptorUtils::base64decode("QUI="), std::vector<unsigned char>({0x41, 0x42})); // "AB"  
    EXPECT_EQ(decryptorUtils::base64decode("QUJD"), std::vector<unsigned char>({0x41, 0x42, 0x43})); // "ABC"
    EXPECT_EQ(decryptorUtils::base64decode("QUJDRA=="), std::vector<unsigned char>({0x41, 0x42, 0x43, 0x44})); // "ABCD"
    
    // "Hello World"
    EXPECT_EQ(decryptorUtils::base64decode("SGVsbG8gV29ybGQ="), helloWorld);
    
    // Binary data
    EXPECT_EQ(decryptorUtils::base64decode("AAECAw=="), std::vector<unsigned char>({0x00, 0x01, 0x02, 0x03}));
    EXPECT_EQ(decryptorUtils::base64decode("///+"), std::vector<unsigned char>({0xFF, 0xFF, 0xFE}));
}

TEST_F(Base64DecodeTest, RoundTripSingleByte) {
    std::string encoded = decryptorUtils::base64encode(singleByte);
    auto decoded = decryptorUtils::base64decode(encoded);
    EXPECT_EQ(decoded, singleByte);
}

TEST_F(Base64DecodeTest, RoundTripTwoBytes) {
    std::string encoded = decryptorUtils::base64encode(twoBytes);
    auto decoded = decryptorUtils::base64decode(encoded);
    EXPECT_EQ(decoded, twoBytes);
}

TEST_F(Base64DecodeTest, RoundTripThreeBytes) {
    std::string encoded = decryptorUtils::base64encode(threeBytes);
    auto decoded = decryptorUtils::base64decode(encoded);
    EXPECT_EQ(decoded, threeBytes);
}

TEST_F(Base64DecodeTest, RoundTripFourBytes) {
    std::string encoded = decryptorUtils::base64encode(fourBytes);
    auto decoded = decryptorUtils::base64decode(encoded);
    EXPECT_EQ(decoded, fourBytes);
}

TEST_F(Base64DecodeTest, RoundTripHelloWorld) {
    std::string encoded = decryptorUtils::base64encode(helloWorld);
    auto decoded = decryptorUtils::base64decode(encoded);
    EXPECT_EQ(decoded, helloWorld);
}

TEST_F(Base64DecodeTest, RoundTripBinaryData) {
    std::string encoded = decryptorUtils::base64encode(binaryData);
    auto decoded = decryptorUtils::base64decode(encoded);
    EXPECT_EQ(decoded, binaryData);
}

TEST_F(Base64DecodeTest, RoundTripLargeData) {
    std::string encoded = decryptorUtils::base64encode(largeData);
    auto decoded = decryptorUtils::base64decode(encoded);
    EXPECT_EQ(decoded, largeData);
}

TEST_F(Base64DecodeTest, PaddingScenarios) {
    // No padding needed (multiple of 3 bytes)
    EXPECT_EQ(decryptorUtils::base64decode("QUJD"), std::vector<unsigned char>({0x41, 0x42, 0x43}));
    
    // One padding character
    EXPECT_EQ(decryptorUtils::base64decode("QUI="), std::vector<unsigned char>({0x41, 0x42}));
    
    // Two padding characters  
    EXPECT_EQ(decryptorUtils::base64decode("QQ=="), std::vector<unsigned char>({0x41}));
}
TEST_F(Base64DecodeTest, WithWhitespace) {
    // OpenSSL typically ignores whitespace in base64
    EXPECT_EQ(decryptorUtils::base64decode("Q Q = ="), std::vector<unsigned char>({0x41}));
    EXPECT_EQ(decryptorUtils::base64decode("Q\nQ\r=\t="), std::vector<unsigned char>({0x41}));
}

TEST_F(Base64DecodeTest, AllValidCharacters) {
    std::string all_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    EXPECT_NO_THROW(decryptorUtils::base64decode(all_chars));
}

TEST_F(Base64DecodeTest, MinimalValidInputs) {
    EXPECT_NO_THROW(decryptorUtils::base64decode("QQ=="));  // 1 byte
    EXPECT_NO_THROW(decryptorUtils::base64decode("QUI="));  // 2 bytes
    EXPECT_NO_THROW(decryptorUtils::base64decode("QUJD"));  // 3 bytes
}
TEST_F(Base64DecodeTest, EmptyInput) {
    EXPECT_THROW(decryptorUtils::base64decode(""), std::runtime_error);
}


TEST_F(Base64DecodeTest, InvalidCharacters) {
    EXPECT_THROW(decryptorUtils::base64decode("QQ@="), std::runtime_error);  // @ is not valid base64
    EXPECT_THROW(decryptorUtils::base64decode("QQ#="), std::runtime_error);  // # is not valid base64
    EXPECT_THROW(decryptorUtils::base64decode("QQ$="), std::runtime_error);  // $ is not valid base64
    EXPECT_THROW(decryptorUtils::base64decode("QQ%="), std::runtime_error);  // % is not valid base64
}

TEST_F(Base64DecodeTest, InvalidPadding) {
    EXPECT_THROW(decryptorUtils::base64decode("Q==="), std::runtime_error);  // Too much padding
    EXPECT_THROW(decryptorUtils::base64decode("QQ=Q"), std::runtime_error);  // Padding in wrong place
    EXPECT_THROW(decryptorUtils::base64decode("Q=Q="), std::runtime_error);  // Padding in wrong place
}

TEST_F(Base64DecodeTest, InvalidLength) {
    EXPECT_THROW(decryptorUtils::base64decode("Q"), std::runtime_error);    // Too short
    EXPECT_THROW(decryptorUtils::base64decode("QQ"), std::runtime_error);   // Invalid length without padding
    EXPECT_THROW(decryptorUtils::base64decode("QQQ"), std::runtime_error);  // Invalid length without padding
}

TEST_F(Base64DecodeTest, MalformedBase64) {
    EXPECT_THROW(decryptorUtils::base64decode("===="), std::runtime_error);  // Only padding
    EXPECT_THROW(decryptorUtils::base64decode("Q=Q="), std::runtime_error);  // Alternating chars and padding
}

TEST_F(Base64DecodeTest, CaseSensitive) {
    auto result1 = decryptorUtils::base64decode("QQ=="); // 'A' = 0x41
    auto result2 = decryptorUtils::base64decode("YQ=="); // 'a' = 0x61
    EXPECT_NE(result1, result2);
    EXPECT_EQ(result1, std::vector<unsigned char>({0x41}));
    EXPECT_EQ(result2, std::vector<unsigned char>({0x61}));
}

// Performance test
TEST_F(Base64DecodeTest, PerformanceTest) {
    std::string large_encoded = decryptorUtils::base64encode(largeData);
    
    auto start = std::chrono::high_resolution_clock::now();
    auto decoded = decryptorUtils::base64decode(large_encoded);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    std::cout << "Decoded " << large_encoded.size() << " base64 chars in " 
              << duration.count() << " ms" << std::endl;
    
    EXPECT_EQ(decoded, largeData);
}

TEST_F(Base64DecodeTest, SpecialBinarySequences) {
    // All zeros
    std::vector<unsigned char> all_zeros(100, 0x00);
    std::string encoded_zeros = decryptorUtils::base64encode(all_zeros);
    auto decoded_zeros = decryptorUtils::base64decode(encoded_zeros);
    EXPECT_EQ(decoded_zeros, all_zeros);
    
    // All 0xFF
    std::vector<unsigned char> all_ff(100, 0xFF);
    std::string encoded_ff = decryptorUtils::base64encode(all_ff);
    auto decoded_ff = decryptorUtils::base64decode(encoded_ff);
    EXPECT_EQ(decoded_ff, all_ff);
    
    // Alternating pattern
    std::vector<unsigned char> alternating;
    for (int i = 0; i < 100; ++i) {
        alternating.push_back(i % 2 ? 0xFF : 0x00);
    }
    std::string encoded_alt = decryptorUtils::base64encode(alternating);
    auto decoded_alt = decryptorUtils::base64decode(encoded_alt);
    EXPECT_EQ(decoded_alt, alternating);
}


