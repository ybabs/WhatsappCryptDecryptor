//
// Created by user on 17/06/2025.
//

#pragma once

#include <string>
#include <array>
#include <charconv>
#include "utils.h"
#include <nlohmann/json.hpp>
#include <vector>
struct FileEntry
{
    std::string path;
    std::array<unsigned char, 16> md5;
    std::uint64_t size;
    std::string metadata;
};

struct BackupInfo
{
    std::string name;
    std::string updateTime;
    nlohmann::json metadata;
    std::vector<FileEntry> files;
};

inline std::uint64_t toU64(const std::string_view sv)
{
    std::uint64_t v{};
    std::from_chars(sv.data(), sv.data() + sv.size(), v);
    return v;
}

inline std::array<unsigned char,16> parseMd5(const std::string& b64md5)
{
    std::string raw = utils::b64(b64md5);
    std::array<unsigned char, 16> out{};
    std::copy_n(raw.begin(), 16, out.begin());
    return out;
}

inline void from_json(const nlohmann::json& j, FileEntry& out)
{
    out.path = j.at("name").get<std::string>();
    const auto& szStr = j.at("sizeBytes").get_ref<const std::string&>();
    out.size = toU64(szStr);
    out.metadata = j.value("metadata", "");
    out.md5      = parseMd5(j.at("md5Hash"));
}
