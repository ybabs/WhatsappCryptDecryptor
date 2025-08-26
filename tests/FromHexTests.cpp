//
// Created by daniel on 7/25/25.
//
#include <gtest/gtest.h>
#include <stdexcept>
#include <vector>
#include "utils.h"


TEST(FromHexTest, EmptyStringReturnsEmptyVector)
{
    std::vector<unsigned char> v = decryptorUtils::fromHex("");
    EXPECT_TRUE(v.empty());
}

TEST(FromHexTest, SingleByteLowercase)
{
    std::vector<unsigned char> v = decryptorUtils::fromHex("1a");
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0], 0x1a);
}

TEST(FromHexTest, SingleByteUppercase) {
    std::vector<unsigned char> v = decryptorUtils::fromHex("FF");
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0], 0xFF);
}

TEST(FromHexTest, MixedCaseMultipleBytes) {
    // "0fA010" → { 0x0f, 0xa0, 0x10 }
    std::vector<unsigned char> expected = { 0x0f, 0xa0, 0x10 };
    std::vector<unsigned char> v = decryptorUtils::fromHex("0fA010");
    EXPECT_EQ(v, expected);
}

TEST(FromHexTest, OddLengthThrows) {
    EXPECT_THROW(decryptorUtils::fromHex("ABC"), std::invalid_argument);
}

TEST(FromHexTest, InvalidHexDigitsAreParsedAsZero) {
    // strtol on "GG" will give 0, so output vector = {0x00}
    std::vector<unsigned char> v = decryptorUtils::fromHex("GG");
    ASSERT_EQ(v.size(), 1u);
    EXPECT_EQ(v[0], 0x00);
}

TEST(FromHexTest, LeadingZeros) {
    // "0001" → {0x00, 0x01}
    std::vector<unsigned char> expected = { 0x00, 0x01 };
    EXPECT_EQ(decryptorUtils::fromHex("0001"), expected);
}
