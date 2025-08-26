#include <gtest/gtest.h>
#include <filesystem>
#include <fstream>
#include <string>
#include <stdexcept>

#include "utils.h"

class ReadTextFileTest: public ::testing::Test
{
protected:
 void SetUp() override
 {

    testDir = std::filesystem::temp_directory_path() / "read_text_file_tests";
    std::filesystem::create_directories(testDir);
    
    // Test file paths
    simpleTextFile = testDir / "simple.txt";
    multiLineTextFile = testDir / "multiline.txt";
    specialCharsFile = testDir / "special_chars.txt";
    unicodeFile = testDir / "unicode.txt";
    emptyFile = testDir / "empty.txt";
    nonExistentFile = testDir / "does_not_exist.txt";
    
    // Create test files
    createTestFiles();

 }

 void TearDown() override 
 {
    std::error_code ec;
    std::filesystem::remove_all(testDir, ec);
 }

  void createTestFiles() 
  {

        // Simple text file
        simpleContent = "Hello, World!";
        std::ofstream simpleFile(simpleTextFile);
        simpleFile << simpleContent;
        simpleFile.close();
        
        // Multi-line text file
        multiLineContent = "Line 1\nLine 2\nLine 3\nFinal line without newline";
        std::ofstream multiLineFile(multiLineTextFile);
        multiLineFile << multiLineContent;
        multiLineFile.close();
        
        // File with special characters
        specialCharsContent = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?\nTabs:\t\tEnd\nQuotes: \"Hello\" and 'World'";
        std::ofstream specialFile(specialCharsFile);
        specialFile << specialCharsContent;
        specialFile.close();
        
        // File with Unicode content (UTF-8)
        unicodeContent = "Unicode: こんにちは世界 🌍 Café naïve résumé";
        std::ofstream unicodeFileStream(unicodeFile);
        unicodeFileStream << unicodeContent;
        unicodeFileStream.close();
        
        // Empty file
        std::ofstream emptyFileStream(emptyFile);
        emptyFileStream.close();
 }

    std::filesystem::path testDir;
    std::filesystem::path simpleTextFile, multiLineTextFile, specialCharsFile;
    std::filesystem::path unicodeFile, emptyFile, nonExistentFile;
    
    std::string simpleContent, multiLineContent, specialCharsContent, unicodeContent;

};

TEST_F(ReadTextFileTest, readSimpleTextFile) {
    auto result = decryptorUtils::readTextFile(simpleTextFile);
    EXPECT_EQ(result, simpleContent);
}

TEST_F(ReadTextFileTest, readMultiLineTextFile) {
    auto result = decryptorUtils::readTextFile(multiLineTextFile);
    EXPECT_EQ(result, multiLineContent);
    
    // Verify newlines are preserved
    EXPECT_TRUE(result.find('\n') != std::string::npos);
}

TEST_F(ReadTextFileTest, readSpecialCharactersFile) {
    auto result = decryptorUtils::readTextFile(specialCharsFile);
    EXPECT_EQ(result, specialCharsContent);
    
    // Verify specific special characters
    EXPECT_TRUE(result.find("!@#$%^&*()") != std::string::npos);
    EXPECT_TRUE(result.find('\t') != std::string::npos);
    EXPECT_TRUE(result.find("\"Hello\"") != std::string::npos);
}

TEST_F(ReadTextFileTest, readUnicodeFile) 
{
    auto result = decryptorUtils::readTextFile(unicodeFile);
    EXPECT_EQ(result, unicodeContent);
    
    // Verify Unicode content is present
    EXPECT_TRUE(result.find("こんにちは世界") != std::string::npos);
    EXPECT_TRUE(result.find("🌍") != std::string::npos);
    EXPECT_TRUE(result.find("Café") != std::string::npos);
}

TEST_F(ReadTextFileTest, differentPathTypes) 
{
    // Test with string path
    std::string stringPath = simpleTextFile.string();
    auto result1 = decryptorUtils::readTextFile(stringPath);
    
    // Test with filesystem::path
    auto result2 = decryptorUtils::readTextFile(simpleTextFile);
    
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result1, simpleContent);
}

TEST_F(ReadTextFileTest, readWhitespaceOnlyFile) 
{
    std::filesystem::path whitespaceFile = testDir / "whitespace.txt";
    std::string whitespaceContent = "   \n\t\r\n   ";
    
    std::ofstream file(whitespaceFile);
    file << whitespaceContent;
    file.close();
    
    auto result = decryptorUtils::readTextFile(whitespaceFile);
    EXPECT_EQ(result, whitespaceContent);
}

TEST_F(ReadTextFileTest, readSingleCharacterFile) 
{
    std::filesystem::path singleCharFile = testDir / "single_char.txt";
    std::string singleChar = "A";
    
    std::ofstream file(singleCharFile);
    file << singleChar;
    file.close();
    
    auto result = decryptorUtils::readTextFile(singleCharFile);
    EXPECT_EQ(result, singleChar);
}

TEST_F(ReadTextFileTest, readNewlineOnlyFile) {
    std::filesystem::path newlineFile = testDir / "newline_only.txt";
    std::string newlineContent = "\n";
    
    std::ofstream file(newlineFile);
    file << newlineContent;
    file.close();
    
    auto result = decryptorUtils::readTextFile(newlineFile);
    EXPECT_EQ(result, newlineContent);
}

TEST_F(ReadTextFileTest, nonExistentFile) {
    EXPECT_THROW(
        decryptorUtils::readTextFile(nonExistentFile),
        std::runtime_error
    );
    
    try {
        decryptorUtils::readTextFile(nonExistentFile);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        std::string errorMsg = e.what();
        EXPECT_TRUE(errorMsg.find("File does not exist") != std::string::npos);
        EXPECT_TRUE(errorMsg.find(nonExistentFile.string()) != std::string::npos);
    }
}

TEST_F(ReadTextFileTest, emptyFile) {
    EXPECT_THROW(
        decryptorUtils::readTextFile(emptyFile),
        std::runtime_error
    );
    
    try {
        decryptorUtils::readTextFile(emptyFile);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        std::string errorMsg = e.what();
        EXPECT_TRUE(errorMsg.find("File Contents are empty") != std::string::npos);
        EXPECT_TRUE(errorMsg.find(emptyFile.string()) != std::string::npos);
    }
}

TEST_F(ReadTextFileTest, directoryInsteadOfFile) {
    EXPECT_THROW(
        decryptorUtils::readTextFile(testDir),
        std::runtime_error
    );
    
    try {
        decryptorUtils::readTextFile(testDir);
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        std::string errorMsg = e.what();
        std::cout << errorMsg << std::endl;
        EXPECT_TRUE(errorMsg.find("underflow error reading the file") != std::string::npos);
    }
}

TEST_F(ReadTextFileTest, multipleReads) 
{
    auto result1 = decryptorUtils::readTextFile(simpleTextFile);
    auto result2 = decryptorUtils::readTextFile(simpleTextFile);
    auto result3 = decryptorUtils::readTextFile(simpleTextFile);
    
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(result2, result3);
    EXPECT_EQ(result1, simpleContent);
}

TEST_F(ReadTextFileTest, longSingleLine) 
{
    std::filesystem::path longLineFile = testDir / "long_line.txt";
    std::string longContent(10000, 'A'); // 10,000 'A' characters
    
    std::ofstream file(longLineFile);
    file << longContent;
    file.close();
    
    auto result = decryptorUtils::readTextFile(longLineFile);
    EXPECT_EQ(result, longContent);
    EXPECT_EQ(result.length(), 10000);
}