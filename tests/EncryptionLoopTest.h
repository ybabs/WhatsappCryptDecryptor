//
// Created by daniel on 7/24/25.
//

#pragma once

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <vector>
#include <array>
#include <string>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <numeric>
#include <iomanip>
#include <sstream>

#include "utils.h"

class EncryptionLoopTest : public ::testing::Test
{
protected:
    void SetUp() override
    {

        // Zero out for predictable tetsing
        testKey.fill(0x00);

        for ( size_t  i = 0; i < altKey.size(); ++i)
        {
            altKey[i] = static_cast<unsigned char>(i);
        }

        testHash = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

        emptyHash.clear();

        largeHash.resize(256);
        std::iota(largeHash.begin(), largeHash.end(), 0);
    }

    // Convert bytes to hex for debugging
    std::string bytesToHex(std::vector<unsigned char>& bytes)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    // manually compute SHA256 for verification
    std::vector<unsigned char> computeSHA256(std::vector<unsigned char>& data)
    {
        std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
        SHA256(data.data(), data.size(), hash.data());
        return hash;
    }

    // concatenate byte arrays
    std::vector<unsigned char> concatenate(const std::array<unsigned char,  Key15::KEY_SIZE>& key,
                                            const std::vector<unsigned char>& hash)
    {
        std::vector<unsigned char> result;
        result.insert(result.end(), key.begin(), key.end());
        result.insert(result.end(), hash.begin(), hash.end());
        return result;
    }

    std::array<unsigned char, Key15::KEY_SIZE> testKey;
    std::array<unsigned char, Key15::KEY_SIZE> altKey;
    std::vector<unsigned char> testHash;
    std::vector<unsigned char> emptyHash;
    std::vector<unsigned char> largeHash;


};