//
// Created by daniel on 7/24/25.
//

#include "EncryptionLoopTest.h"

TEST_F(EncryptionLoopTest, ZeroOutputBytes_ReturnsEmptyVector)
{
    auto result = decryptorUtils::encryptionLoop(testKey, testHash, 0);

    EXPECT_TRUE(result.empty());
    EXPECT_EQ(result.size(), 0);
}

TEST_F(EncryptionLoopTest, SingleDigestLength_ReturnsOneHash)
{
    const auto outputBytes = SHA256_DIGEST_LENGTH ;
    auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);
    EXPECT_EQ(result.size(),  SHA256_DIGEST_LENGTH);

    auto combined = concatenate(testKey, testHash);
    auto expectedHash = computeSHA256(combined);
    EXPECT_EQ(result, expectedHash);
}

TEST_F(EncryptionLoopTest,TwoDigests_ReturnsTwoHashes)
{
    const size_t outputBytes = 2 * SHA256_DIGEST_LENGTH; // 64 bytes
    auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);
    // First 32 Bytes should be SHA256(key + hash)
    std::vector<unsigned char>firstDigest(result.begin(), result.begin() + SHA256_DIGEST_LENGTH);
    auto combined = concatenate(testKey, testHash);
    auto expectedFirstHash = computeSHA256(combined);

    // Second 32 bytes should be SHA256(FirstFigest)
    std::vector<unsigned char> secondDigest(result.begin() + SHA256_DIGEST_LENGTH, result.end());
    auto expectedSecondHash = computeSHA256(expectedFirstHash);
    EXPECT_EQ(secondDigest, expectedSecondHash);
}

TEST_F(EncryptionLoopTest, PartialDigestLength_TruncatesCorrectly)
{
    const size_t outputBytes = SHA256_DIGEST_LENGTH + 10;
    auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);

    // First 32 Bytes should be complete first Digest
    std::vector<unsigned char> firstDigest(result.begin(), result.begin() + SHA256_DIGEST_LENGTH);
    auto combined = concatenate(testKey, testHash);
    auto expectedFirstHash = computeSHA256(combined);
    EXPECT_EQ(firstDigest, expectedFirstHash);

    // Remaining 10 bytes should be the truncated stuff
    std::vector<unsigned char> secondDigest(result.begin() + SHA256_DIGEST_LENGTH, result.end());
    auto fullSecondHash = computeSHA256(expectedFirstHash);
    std::vector<unsigned char> expectedPartialSecond(fullSecondHash.begin(), fullSecondHash.begin() + 10);
    EXPECT_EQ(secondDigest, expectedPartialSecond);
}

TEST_F(EncryptionLoopTest, EmptyFileHash_WorksCorrectly)
{
    const size_t outputBytes = SHA256_DIGEST_LENGTH;
    auto result = decryptorUtils::encryptionLoop(testKey, emptyHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);

    // This should compute SHA256(key + empty) and give only SHA256(Key)
    std::vector<unsigned char> keyOnly(testKey.begin(), testKey.end());
    auto expectedHash = computeSHA256(keyOnly);
    EXPECT_EQ(result, expectedHash);
}

TEST_F(EncryptionLoopTest, LargeFileHash_WorksCorrectly)
{
    const size_t outputBytes = SHA256_DIGEST_LENGTH;
    auto result = decryptorUtils::encryptionLoop(testKey, largeHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);
    EXPECT_FALSE(result.empty());

    auto combined = concatenate(testKey, largeHash);
    auto expectedHash = computeSHA256(combined);
    EXPECT_EQ(result, expectedHash);
}

TEST_F(EncryptionLoopTest, VeryLargeOutput_GeneratesCorrectly) {
    const size_t outputBytes = 10 * SHA256_DIGEST_LENGTH; // 320 bytes
    auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);

    auto combined = concatenate(testKey, testHash);
    auto firstHash = computeSHA256(combined);

    std::vector<unsigned char> firstDigest(result.begin(), result.begin() + SHA256_DIGEST_LENGTH);
    EXPECT_EQ(firstDigest, firstHash);

    auto secondHash = computeSHA256(firstHash);
    std::vector<unsigned char> secondDigest(result.begin() + SHA256_DIGEST_LENGTH,
                                           result.begin() + 2 * SHA256_DIGEST_LENGTH);
    EXPECT_EQ(secondDigest, secondHash);
}

TEST_F(EncryptionLoopTest, SingleByte_Output) {
    const size_t outputBytes = 1;
    auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);

    // Should be first byte of SHA256(key + hash)
    auto combined = concatenate(testKey, testHash);
    auto fullHash = computeSHA256(combined);
    EXPECT_EQ(result[0], fullHash[0]);
}

TEST_F(EncryptionLoopTest, DeterministicOutput_SameInputsSameOutput)
{
    const size_t outputBytes = 100;

    auto result1 = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);
    auto result2 = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);

    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result1.size(), outputBytes);
    EXPECT_EQ(result2.size(), outputBytes);
}

TEST_F(EncryptionLoopTest, DifferentKeys_ProduceDifferentOutput)
{
    const size_t outputBytes = SHA256_DIGEST_LENGTH;

    auto result1 = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);
    auto result2 = decryptorUtils::encryptionLoop(altKey, testHash, outputBytes);

    EXPECT_NE(result1, result2);
    EXPECT_EQ(result1.size(), outputBytes);
    EXPECT_EQ(result2.size(), outputBytes);
}

TEST_F(EncryptionLoopTest, DifferentHashes_ProduceDifferentOutput) {
    const size_t outputBytes = SHA256_DIGEST_LENGTH;
    std::vector<unsigned char> altHash = {0xFF, 0xEE, 0xDD, 0xCC};

    auto result1 = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);
    auto result2 = decryptorUtils::encryptionLoop(testKey, altHash, outputBytes);

    EXPECT_NE(result1, result2);
    EXPECT_EQ(result1.size(), outputBytes);
    EXPECT_EQ(result2.size(), outputBytes);
}

TEST_F(EncryptionLoopTest, LargeOutput_DoesNotCrash) {
    const size_t outputBytes = 10000; // 10KB

    EXPECT_NO_THROW({
        auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);
        EXPECT_EQ(result.size(), outputBytes);
    });
}

TEST_F(EncryptionLoopTest, PrimeBoundary_OutputSizes) {
    // Test with prime numbers to catch off-by-one errors
    std::vector<size_t> primeSizes = {31, 37, 41, 43, 47, 53, 59, 61, 67, 71};

    for (size_t outputBytes : primeSizes) {
        auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);
        EXPECT_EQ(result.size(), outputBytes) << "Failed for output size: " << outputBytes;
    }
}

TEST_F(EncryptionLoopTest, CommonWhatsAppSizes_48Bytes) {
    // WhatsApp commonly uses 48 bytes for key+IV derivation
    const size_t outputBytes = 48;
    auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);

    // Should be 1.5 SHA256 digests (32 + 16 bytes)
    EXPECT_GT(result.size(), SHA256_DIGEST_LENGTH);
    EXPECT_LT(result.size(), 2 * SHA256_DIGEST_LENGTH);
}

TEST_F(EncryptionLoopTest, CommonWhatsAppSizes_64Bytes) {
    // Another common size - exactly 2 digests
    const size_t outputBytes = 64;
    auto result = decryptorUtils::encryptionLoop(testKey, testHash, outputBytes);

    EXPECT_EQ(result.size(), outputBytes);
    EXPECT_EQ(result.size(), 2 * SHA256_DIGEST_LENGTH);
}



