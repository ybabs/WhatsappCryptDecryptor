#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <chrono>
#include <string>

#include "utils.h" 

namespace {

// Small helper to assert that a std::runtime_error contains a substring.
void expect_runtime_error_with_substr(std::function<void()> fn, const std::string& needle) {
    try {
        fn();
        FAIL() << "Expected std::runtime_error";
    } catch (const std::runtime_error& e) {
        std::string msg = e.what();
        EXPECT_NE(msg.find(needle), std::string::npos)
            << "Expected error message to contain: \"" << needle
            << "\" but got: \"" << msg << "\"";
    } catch (...) {
        FAIL() << "Expected std::runtime_error, caught something else.";
    }
}

}

TEST(GetMetadataInfo, ParsesZuluTimestamp) {
    nlohmann::json j = {
        {"name", "folder/file.bin"},
        {"updateTime", "2024-02-03T10:20:30Z"}
    };

    auto info = decryptorUtils::getMetadataInfo(j);

    EXPECT_EQ(info.originalPath, "folder/file.bin");

    // Expected time computed with the same parser (validates forwarding/assignment).
    auto expected_tp = decryptorUtils::parseISO8601("2024-02-03T10:20:30Z");
    EXPECT_EQ(info.creationTime, expected_tp);
}

TEST(GetMetadataInfo, ParsesOffsetTimestamp) {
    nlohmann::json j = {
        {"name", "/abs/path"},
        {"updateTime", "2024-02-03T10:20:30+01:30"}
    };

    auto info = decryptorUtils::getMetadataInfo(j);

    EXPECT_EQ(info.originalPath, "/abs/path");

    auto expected_tp = decryptorUtils::parseISO8601("2024-02-03T10:20:30+01:30");
    EXPECT_EQ(info.creationTime, expected_tp);
}

TEST(GetMetadataInfo, ParsesFractionalSeconds) {
    nlohmann::json j = {
        {"name", "some/where"},
        {"updateTime", "2024-02-03T10:20:30.123456Z"}
    };

    auto info = decryptorUtils::getMetadataInfo(j);
    EXPECT_EQ(info.originalPath, "some/where");

    auto expected_tp = decryptorUtils::parseISO8601("2024-02-03T10:20:30.123456Z");
    EXPECT_EQ(info.creationTime, expected_tp);
}

TEST(GetMetadataInfo, IgnoresExtraFields) {
    nlohmann::json j = {
        {"name", "x/y/z.bin"},
        {"updateTime", "2024-09-10T12:34:56Z"},
        {"unrelated", 42},
        {"nested", {{"a", 1}, {"b", true}}}
    };

    auto info = decryptorUtils::getMetadataInfo(j);
    EXPECT_EQ(info.originalPath, "x/y/z.bin");

    auto expected_tp = decryptorUtils::parseISO8601("2024-09-10T12:34:56Z");
    EXPECT_EQ(info.creationTime, expected_tp);
}


TEST(GetMetadataInfo, ThrowsWhenNameMissing) {
    nlohmann::json j = {
        {"updateTime", "2024-02-03T10:20:30Z"}
    };

    EXPECT_THROW((void)decryptorUtils::getMetadataInfo(j), std::runtime_error);
}

TEST(GetMetadataInfo, ThrowsWhenNameNotString) {
    nlohmann::json j = {
        {"name", 123},
        {"updateTime", "2024-02-03T10:20:30Z"}
    };

    EXPECT_THROW((void)decryptorUtils::getMetadataInfo(j), std::runtime_error);
}

TEST(GetMetadataInfo, ThrowsWhenNameEmpty) {
    nlohmann::json j = {
        {"name", ""},
        {"updateTime", "2024-02-03T10:20:30Z"}
    };

    expect_runtime_error_with_substr(
        [&]{ (void)decryptorUtils::getMetadataInfo(j); },
        "original path"
    );
}

TEST(GetMetadataInfo, ThrowsWhenUpdateTimeMissing) {
    nlohmann::json j = {
        {"name", "file.bin"}
    };

    EXPECT_THROW((void)decryptorUtils::getMetadataInfo(j), std::runtime_error);
}

TEST(GetMetadataInfo, ThrowsWhenUpdateTimeNotString) {
    nlohmann::json j = {
        {"name", "file.bin"},
        {"updateTime", 123}
    };

    EXPECT_THROW((void)decryptorUtils::getMetadataInfo(j), std::runtime_error);
}

TEST(GetMetadataInfo, ThrowsWhenUpdateTimeEmpty) {
    nlohmann::json j = {
        {"name", "file.bin"},
        {"updateTime", ""}
    };

    expect_runtime_error_with_substr(
        [&]{ (void)decryptorUtils::getMetadataInfo(j); },
        "updateTime field and cannot be empty"
    );
}

TEST(GetMetadataInfo, ThrowsWhenUpdateTimeInvalidFormat) {
    nlohmann::json j = {
        {"name", "file.bin"},
        {"updateTime", "not-an-iso8601"}
    };

    // Ensure the error path that wraps parse failure is taken.
    expect_runtime_error_with_substr(
        [&]{ (void)decryptorUtils::getMetadataInfo(j); },
        "Failed to parse metadata updateTime:"
    );
}