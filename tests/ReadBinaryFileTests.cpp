#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <random>
#include <thread>
#include <atomic>

#include "utils.h"


class ReadBinaryFileTest : public ::testing::Test
{
protected:

void SetUp() override
{

    testDir = std::filesystem::temp_directory_path() / "read_binary_file_tests";
        std::filesystem::create_directories(testDir);
        
        // Test file paths
        existingTextFile = testDir / "existing_text.txt";
        existingBinaryFile = testDir / "existing_binary.bin";
        emptyFile = testDir / "empty_file.txt";
        largeFile = testDir / "large_file.bin";
        nonExistentFile = testDir / "does_not_exist.txt";
        specialCharsFile = testDir / "special_chars_file.bin";
        
        // Create test files
        createTestFiles();

}

void TearDown() override
{
    std::error_code ec;
    std::filesystem::remove_all(testDir, ec);
}

void createTestFiles() {
        // Create text file with known content
        textFileContent = "Hello, World!\nThis is a test file.\nWith multiple lines.";
        std::ofstream textFile(existingTextFile);
        textFile << textFileContent;
        textFile.close();
        
        // Create binary file with known binary data
        binaryFileContent = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0xFF
        };
        std::ofstream binaryFile(existingBinaryFile, std::ios::binary);
        binaryFile.write(reinterpret_cast<const char*>(binaryFileContent.data()), binaryFileContent.size());
        binaryFile.close();
        
        // Create empty file
        std::ofstream emptyFileStream(emptyFile);
        emptyFileStream.close();
        
        // Create large file (1MB)
        largeFileContent.resize(1024 * 1024);
        std::random_device randomDevice;
        std::mt19937 generator(randomDevice());
        std::uniform_int_distribution<> distribution(0, 255);
        for (size_t i = 0; i < largeFileContent.size(); ++i) {
            largeFileContent[i] = static_cast<unsigned char>(distribution(generator));
        }
        std::ofstream largeFileStream(largeFile, std::ios::binary);
        largeFileStream.write(reinterpret_cast<const char*>(largeFileContent.data()), largeFileContent.size());
        largeFileStream.close();
        
        // Create file with special characters and binary data
        specialCharsContent = {
            0x00, 0xFF, 0x7F, 0x80, 0x01, 0xFE, 0x02, 0xFD,
            'H', 'e', 'l', 'l', 'o', '\n', '\r', '\t',
            0xC2, 0xA9, // UTF-8 copyright symbol
            0xE2, 0x82, 0xAC, // UTF-8 euro symbol
            0x00, 0x00, 0x00, 0x00 // Null bytes
        };
        std::ofstream specialFile(specialCharsFile, std::ios::binary);
        specialFile.write(reinterpret_cast<const char*>(specialCharsContent.data()), specialCharsContent.size());
        specialFile.close();
    }


    std::filesystem::path testDir;
    std::filesystem::path existingTextFile, existingBinaryFile, emptyFile;
    std::filesystem::path largeFile, nonExistentFile, specialCharsFile;
    
    std::string textFileContent;
    std::vector<unsigned char> binaryFileContent;
    std::vector<unsigned char> largeFileContent;
    std::vector<unsigned char> specialCharsContent;
};

TEST_F(ReadBinaryFileTest, readExistingTextFile) {
    auto result = decryptorUtils::readBinaryFile(existingTextFile);
    
    // Convert expected string to unsigned char vector for comparison
    std::vector<unsigned char> expectedContent(textFileContent.begin(), textFileContent.end());
    
    EXPECT_EQ(result, expectedContent);
    EXPECT_EQ(result.size(), textFileContent.size());
}

TEST_F(ReadBinaryFileTest, readExistingBinaryFile) {
    auto result = decryptorUtils::readBinaryFile(existingBinaryFile);
    
    EXPECT_EQ(result, binaryFileContent);
    EXPECT_EQ(result.size(), binaryFileContent.size());
}

TEST_F(ReadBinaryFileTest, readEmptyFile) {
    auto result = decryptorUtils::readBinaryFile(emptyFile);
    
    EXPECT_TRUE(result.empty());
    EXPECT_EQ(result.size(), 0);
}

TEST_F(ReadBinaryFileTest, readLargeFile) {
    auto result = decryptorUtils::readBinaryFile(largeFile);
    
    EXPECT_EQ(result, largeFileContent);
    EXPECT_EQ(result.size(), largeFileContent.size());
    EXPECT_EQ(result.size(), 1024 * 1024);
}

TEST_F(ReadBinaryFileTest, readSpecialCharactersFile) {
    auto result = decryptorUtils::readBinaryFile(specialCharsFile);
    
    EXPECT_EQ(result, specialCharsContent);
    EXPECT_EQ(result.size(), specialCharsContent.size());
    
    // Verify specific bytes are preserved
    EXPECT_EQ(result[0], 0x00);  // Null byte
    EXPECT_EQ(result[1], 0xFF);  // Max byte value
    EXPECT_EQ(result[result.size() - 1], 0x00);  // Last null byte
}

TEST_F(ReadBinaryFileTest, differentPathTypes) {
    // Test with string path
    std::string stringPath = existingTextFile.string();
    auto result1 = decryptorUtils::readBinaryFile(stringPath);
    
    // Test with filesystem::path
    auto result2 = decryptorUtils::readBinaryFile(existingTextFile);
    
    // Test with relative path (if applicable)
    std::filesystem::current_path(testDir);
    auto result3 = decryptorUtils::readBinaryFile("existing_text.txt");
    
    // All should produce the same result
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result2, result3);
}

TEST_F(ReadBinaryFileTest, variousFileSizes) {
    // Create files of different sizes
    std::vector<size_t> fileSizes = {1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65, 
                                     127, 128, 129, 255, 256, 257, 511, 512, 513, 
                                     1023, 1024, 1025, 4095, 4096, 4097};
    
    for (size_t fileSize : fileSizes) {
        std::filesystem::path testFile = testDir / ("size_" + std::to_string(fileSize) + ".bin");
        
        // Create test data
        std::vector<unsigned char> testData(fileSize);
        for (size_t i = 0; i < fileSize; ++i) {
            testData[i] = static_cast<unsigned char>(i % 256);
        }
        
        // Write test file
        std::ofstream file(testFile, std::ios::binary);
        file.write(reinterpret_cast<const char*>(testData.data()), testData.size());
        file.close();
        
        // Read and verify
        auto result = decryptorUtils::readBinaryFile(testFile);
        EXPECT_EQ(result, testData) << "Failed for file size: " << fileSize;
        EXPECT_EQ(result.size(), fileSize) << "Wrong size for file size: " << fileSize;
    }
}

TEST_F(ReadBinaryFileTest, nonExistentFile) {
    EXPECT_THROW(
        decryptorUtils::readBinaryFile(nonExistentFile),
        std::runtime_error
    );
    
    try {
        decryptorUtils::readBinaryFile(nonExistentFile);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        std::string errorMsg = e.what();
        EXPECT_TRUE(errorMsg.find("File does not exist") != std::string::npos);
        EXPECT_TRUE(errorMsg.find(nonExistentFile.string()) != std::string::npos);
    }
}

TEST_F(ReadBinaryFileTest, directoryInsteadOfFile) {
    EXPECT_THROW(
        decryptorUtils::readBinaryFile(testDir),
        std::runtime_error
    );
}

TEST_F(ReadBinaryFileTest, pathsWithSpecialCharacters) {
    std::filesystem::path specialPath = testDir / "file with spaces & symbols!@#.txt";
    
    // Create file
    std::string testContent = "Special path test content";
    std::ofstream file(specialPath);
    file << testContent;
    file.close();
    
    auto result = decryptorUtils::readBinaryFile(specialPath);
    std::vector<unsigned char> expectedContent(testContent.begin(), testContent.end());
    
    EXPECT_EQ(result, expectedContent);
}

TEST_F(ReadBinaryFileTest, multipleReads) {
    auto result1 = decryptorUtils::readBinaryFile(existingBinaryFile);
    auto result2 = decryptorUtils::readBinaryFile(existingBinaryFile);
    auto result3 = decryptorUtils::readBinaryFile(existingBinaryFile);
    
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result2, result3);
    EXPECT_EQ(result1, binaryFileContent);
}

TEST_F(ReadBinaryFileTest, specificByteValues) {
    // Test file with all zeros
    std::filesystem::path zeroFile = testDir / "all_zeros.bin";
    std::vector<unsigned char> zeroContent(1000, 0x00);
    std::ofstream zeroFileStream(zeroFile, std::ios::binary);
    zeroFileStream.write(reinterpret_cast<const char*>(zeroContent.data()), zeroContent.size());
    zeroFileStream.close();
    
    auto zeroResult = decryptorUtils::readBinaryFile(zeroFile);
    EXPECT_EQ(zeroResult, zeroContent);
    
    // Test file with all 0xFF
    std::filesystem::path ffFile = testDir / "all_ff.bin";
    std::vector<unsigned char> ffContent(1000, 0xFF);
    std::ofstream ffFileStream(ffFile, std::ios::binary);
    ffFileStream.write(reinterpret_cast<const char*>(ffContent.data()), ffContent.size());
    ffFileStream.close();
    
    auto ffResult = decryptorUtils::readBinaryFile(ffFile);
    EXPECT_EQ(ffResult, ffContent);
}

TEST_F(ReadBinaryFileTest, errorMessageContent) {
    // Test non-existent file error message
    try {
        decryptorUtils::readBinaryFile(nonExistentFile);
        FAIL() << "Expected exception";
    } catch (const std::runtime_error& e) {
        std::string errorMsg = e.what();
        EXPECT_TRUE(errorMsg.find("File does not exist") != std::string::npos);
        EXPECT_TRUE(errorMsg.find(nonExistentFile.string()) != std::string::npos);
    }
    
    // Test directory error message
    try {
        decryptorUtils::readBinaryFile(testDir);
        FAIL() << "Expected exception";
    } catch (const std::runtime_error& e) {
        std::string errorMsg = e.what();
        EXPECT_TRUE(errorMsg.find("cannot get file size") != std::string::npos);
        EXPECT_TRUE(errorMsg.find(testDir.string()) != std::string::npos);
    }
}

TEST_F(ReadBinaryFileTest, readAfterCreation) {
    std::filesystem::path newFile = testDir / "newly_created.bin";
    std::vector<unsigned char> testData = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE};
    
    // Create and immediately read
    std::ofstream file(newFile, std::ios::binary);
    file.write(reinterpret_cast<const char*>(testData.data()), testData.size());
    file.close();
    
    auto result = decryptorUtils::readBinaryFile(newFile);
    EXPECT_EQ(result, testData);
}