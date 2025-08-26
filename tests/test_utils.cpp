//
// Created by daniel on 6/12/25.
//
#include <gtest/gtest.h>
#include "utils.h"
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <cstring>

static std::filesystem::path writeTempFile(const std::string& contents)
{
    auto p = std::filesystem::temp_directory_path() / "test.tmp";
    std::ofstream ofs(p, std::ios::binary);
    ofs << contents;
    ofs.close();
    return p;
}

TEST(UtilsTest, SizeofFmtBasic)
{
    EXPECT_EQ(decryptorUtils::sizeofFmt(500), "500.0 B");
    EXPECT_EQ(decryptorUtils::sizeofFmt(100), "100.0 B");
    EXPECT_EQ(decryptorUtils::sizeofFmt(1536), "1.5 KiB");
    EXPECT_EQ(decryptorUtils::sizeofFmt(1024*1024), "1.0 MiB");
}

TEST(UtilsTest, GenerateAndroidUidIsHex)
{
    auto uid = decryptorUtils::generateAndroidUid();
    // SHould be exactly 16 hex chars
    EXPECT_EQ(uid.size(), 16u);
    EXPECT_TRUE(std::all_of(uid.begin(), uid.end(), ::isxdigit));
}

TEST(UtilsTest, CropStringWorks)
{
    std::string s = "abcdefghijklmnop";
    // crop to 8 chars, use ".." as ellipsis
    EXPECT_EQ(decryptorUtils::cropString(s, 8, ".."), "..klmnop");
    EXPECT_EQ(decryptorUtils::cropString("short", 10, ".."), "short");
}

TEST(UtilsTest, Md5FromFileReturnsCorrectHash)
{
    auto tmp = writeTempFile("hello");
    auto md5 = decryptorUtils::getMd5FromFile(tmp);

    ASSERT_EQ(md5.size(), 16u);
    static constexpr unsigned char expected[16] = {
        0x5d, 0x41, 0x40, 0x2a,
        0xbc, 0x4b, 0x2a, 0x76,
        0xb9, 0x71, 0x9d, 0x91,
        0x10, 0x17, 0xc5, 0x92
    };

    EXPECT_EQ(0, std::memcmp(md5.data(), expected, 16));


}