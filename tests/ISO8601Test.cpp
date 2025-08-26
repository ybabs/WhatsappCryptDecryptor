//
// Created by daniel on 7/25/25.
//

#include <gtest/gtest.h>
#include <chrono>
#include <ctime>
#include <stdexcept>
#include "utils.h"

static std::tm toUtcTm(const std::chrono::system_clock::time_point& tp) {
    auto tt = std::chrono::system_clock::to_time_t(tp);
    std::tm buf;
#if defined(_WIN32)
    gmtime_s(&buf, &tt);
#else
    gmtime_r(&tt, &buf);
#endif
    return buf;
}


TEST(ParseISO8601Test, Epoch) {
    // 1970‑01‑01T00:00:00 should map to the epoch
    const auto tp = decryptorUtils::parseISO8601("1970-01-01T00:00:00");
    EXPECT_EQ(tp, std::chrono::system_clock::time_point{});
}

TEST(ParseISO8601Test, KnownTimestamp) {
    // Verify the individual date/time fields for a known string
    const std::string s = "2025-07-25T15:30:45";
    const auto tp = decryptorUtils::parseISO8601(s);
    std::tm utc = toUtcTm(tp);
    EXPECT_EQ(utc.tm_year + 1900, 2025);
    EXPECT_EQ(utc.tm_mon  + 1,    7);
    EXPECT_EQ(utc.tm_mday,        25);
    EXPECT_EQ(utc.tm_hour,        15);
    EXPECT_EQ(utc.tm_min,         30);
    EXPECT_EQ(utc.tm_sec,         45);
}

TEST(ParseISO8601Test, LeapDay) {
    // Feb 29 on a leap year should parse just fine
    auto tp = decryptorUtils::parseISO8601("2000-02-29T12:00:00");
    std::tm utc = toUtcTm(tp);
    EXPECT_EQ(utc.tm_year + 1900, 2000);
    EXPECT_EQ(utc.tm_mon  + 1,    2);
    EXPECT_EQ(utc.tm_mday,        29);
}

TEST(ParseISO8601Test, InvalidFormatThrows) {
    EXPECT_THROW(decryptorUtils::parseISO8601("not-a-date"), std::runtime_error);
}

TEST(ParseISO8601Test, MissingSecondsThrows) {

    EXPECT_THROW(decryptorUtils::parseISO8601("2025-07-25T15:30"), std::runtime_error);
}

TEST(ParseISO8601Test, InvalidCalendarDateThrows) {
    // February 30th doesn’t exist
    EXPECT_THROW(decryptorUtils::parseISO8601("2025-02-30T00:00:00"), std::runtime_error);
}
