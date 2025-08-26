#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <thread>

#include "utils.h"

class FileTimeConversionTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
    
    // Helper function to compare time points with tolerance
    bool areTimePointsClose(const std::filesystem::file_time_type& a, 
                           const std::filesystem::file_time_type& b, 
                           std::chrono::milliseconds tolerance = std::chrono::milliseconds(100)) {
        auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
            (a > b) ? (a - b) : (b - a));
        return diff <= tolerance;
    }

};

TEST_F(FileTimeConversionTest, convertsCurrentSystemTime) {
    auto now = std::chrono::system_clock::now();
    auto fileTime = decryptorUtils::convertToFileTime(now);
    
    // The result should be a valid file_time_type
    EXPECT_TRUE(fileTime.time_since_epoch().count() != 0);
}

TEST_F(FileTimeConversionTest, convertsEpochTime) {
    auto epoch = std::chrono::system_clock::time_point{};
    auto fileTime = decryptorUtils::convertToFileTime(epoch);
    
    // Should handle epoch time without crashing
    EXPECT_NO_THROW(decryptorUtils::convertToFileTime(epoch));
}

TEST_F(FileTimeConversionTest, convertsPastTime) {
    auto past = std::chrono::system_clock::now() - std::chrono::hours(24);
    auto fileTime = decryptorUtils::convertToFileTime(past);
    
    // Should handle past times
    EXPECT_NO_THROW(decryptorUtils::convertToFileTime(past));
}

TEST_F(FileTimeConversionTest, handlesHighPrecisionTime) {
    auto now = std::chrono::system_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch());
    auto preciseTime = std::chrono::system_clock::time_point(nanos);
    
    EXPECT_NO_THROW(decryptorUtils::convertToFileTime(preciseTime));
}

TEST_F(FileTimeConversionTest, handlesTimeAroundEpoch) {
    // Test times around Unix epoch
    auto beforeEpoch = std::chrono::system_clock::from_time_t(-86400); // 1 day before epoch
    auto afterEpoch = std::chrono::system_clock::from_time_t(86400);   // 1 day after epoch
    
    EXPECT_NO_THROW(decryptorUtils::convertToFileTime(beforeEpoch));
    EXPECT_NO_THROW(decryptorUtils::convertToFileTime(afterEpoch));
}

