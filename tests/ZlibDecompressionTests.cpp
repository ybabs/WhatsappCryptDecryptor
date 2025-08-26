#include <gtest/gtest.h>
#include <zlib.h>
#include <vector>
#include <string>
#include <stdexcept>
#include <algorithm>
#include <random>
#include <thread>
#include <atomic>

#include "utils.h"

class ZlibDecompressTest : public ::testing::Test {
protected:
    void SetUp() override {}
    
    void TearDown() override {}
    
    // Helper function to create a vector from string
    std::vector<unsigned char> stringToVector(const std::string& str) {
        return std::vector<unsigned char>(str.begin(), str.end());
    }
    
    // Helper function to create random data
    std::vector<unsigned char> createRandomData(size_t length) {
        std::vector<unsigned char> result(length);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        for (size_t i = 0; i < length; ++i) {
            result[i] = static_cast<unsigned char>(dis(gen));
        }
        return result;
    }
    
    // Helper function to compress data using zlib
    std::vector<unsigned char> zlibCompress(const std::vector<unsigned char>& data, int level = Z_DEFAULT_COMPRESSION) {
        if (data.empty()) {
            return {};
        }
        
        z_stream stream {};
        stream.zalloc = Z_NULL;
        stream.zfree = Z_NULL;
        stream.opaque = Z_NULL;
        
        int ret = deflateInit(&stream, level);
        if (ret != Z_OK) {
            throw std::runtime_error("Failed to initialize zlib compression");
        }
        
        struct ZlibCompressCleanup {
            z_stream* mStream;
            ~ZlibCompressCleanup() { if (mStream) deflateEnd(mStream); }
        } cleanup(&stream);
        
        std::vector<unsigned char> compressed;
        const size_t chunkSize = 65536;
        std::vector<unsigned char> buffer(chunkSize);
        
        stream.avail_in = static_cast<uInt>(data.size());
        stream.next_in = const_cast<Bytef*>(data.data());
        
        do {
            stream.avail_out = static_cast<uInt>(chunkSize);
            stream.next_out = buffer.data();
            
            ret = deflate(&stream, Z_FINISH);
            if (ret == Z_STREAM_ERROR) {
                throw std::runtime_error("Compression failed");
            }
            
            size_t have = chunkSize - stream.avail_out;
            compressed.insert(compressed.end(), buffer.begin(), buffer.begin() + have);
        } while (stream.avail_out == 0);
        
        if (ret != Z_STREAM_END) {
            throw std::runtime_error("Compression incomplete");
        }
        
        return compressed;
    }
    
    std::vector<unsigned char> createRepeatingData(const std::string& pattern, size_t totalSize) {
    if (pattern.empty()) {
        throw std::invalid_argument("pattern must not be empty");
    }
    std::vector<unsigned char> result;
    result.reserve(totalSize);
    while (result.size() < totalSize) {
        for (char c : pattern) {
            if (result.size() >= totalSize) break;
            result.push_back(static_cast<unsigned char>(c));
        }
    }
    return result;
}

};

TEST_F(ZlibDecompressTest, decompressesValidData) 
{
    auto originalData = stringToVector("Hello, World! This is a test message for zlib compression and decompression.");
    auto compressedData = zlibCompress(originalData);
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(originalData, decompressedData);
}

TEST_F(ZlibDecompressTest, throwsOnEmptyCompressedData) 
{
    std::vector<unsigned char> emptyData;
    
    EXPECT_THROW(decryptorUtils::zlibDecompress(emptyData), std::runtime_error);
}

TEST_F(ZlibDecompressTest, throwsOnInvalidCompressedData) 
{
    auto invalidData = createRandomData(100); // Random data, not compressed
    
    EXPECT_THROW(decryptorUtils::zlibDecompress(invalidData), std::runtime_error);
}

TEST_F(ZlibDecompressTest, throwsOnCorruptedData) 
{
    auto originalData = stringToVector("Test data for corruption");
    auto compressedData = zlibCompress(originalData);
    
    // Corrupt the middle of the compressed data
    if (compressedData.size() > 10) {
        compressedData[compressedData.size() / 2] ^= 0xFF;
    }
    
    EXPECT_THROW(decryptorUtils::zlibDecompress(compressedData), std::runtime_error);
}

TEST_F(ZlibDecompressTest, throwsOnTruncatedData) 
{
    auto originalData = stringToVector("Test data for truncation testing");
    auto compressedData = zlibCompress(originalData);
    
    // Truncate the compressed data
    if (compressedData.size() > 5) {
        compressedData.resize(compressedData.size() - 5);
    }
    
    EXPECT_THROW(decryptorUtils::zlibDecompress(compressedData), std::runtime_error);
}

TEST_F(ZlibDecompressTest, handlesSmallData) 
{
    auto originalData = stringToVector("Hi");
    auto compressedData = zlibCompress(originalData);
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(originalData, decompressedData);
}

TEST_F(ZlibDecompressTest, handlesLargeData) 
{
    size_t largeSize = 1024 * 1024; // 1MB
    auto originalData = createRepeatingData("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", largeSize);
    auto compressedData = zlibCompress(originalData);
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(originalData, decompressedData);
}

TEST_F(ZlibDecompressTest, handlesBinaryDataWithNullBytes) {
    std::vector<unsigned char> binaryData = {0x00, 0x01, 0x02, 0x00, 0xFF, 0x00, 0xAB, 0xCD, 0x00};
    auto compressedData = zlibCompress(binaryData);
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(binaryData, decompressedData);
}

TEST_F(ZlibDecompressTest, handlesHighlyCompressibleData) {
    // Create data with lots of repetition
    auto originalData = createRepeatingData("A", 10000);
    auto compressedData = zlibCompress(originalData);
    
    // Verify compression actually happened
    EXPECT_LT(compressedData.size(), originalData.size());
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(originalData, decompressedData);
}

TEST_F(ZlibDecompressTest, handlesPoorlyCompressibleData) {
    auto originalData = createRandomData(1000); // Random data compresses poorly
    auto compressedData = zlibCompress(originalData);
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(originalData, decompressedData);
}

TEST_F(ZlibDecompressTest, handlesVariousCompressionLevels) {
    auto originalData = stringToVector("Test data for various compression levels testing");
    
    std::vector<int> compressionLevels = {Z_NO_COMPRESSION, Z_BEST_SPEED, Z_DEFAULT_COMPRESSION, Z_BEST_COMPRESSION};
    
    for (int level : compressionLevels) {
        auto compressedData = zlibCompress(originalData, level);
        auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
        
        EXPECT_EQ(originalData, decompressedData) << "Failed for compression level: " << level;
    }
}

TEST_F(ZlibDecompressTest, handlesDataAtChunkBoundary) {
    size_t chunkSize = 65536; // Same as in the function
    auto originalData = createRepeatingData("TEST", chunkSize);
    auto compressedData = zlibCompress(originalData);
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(originalData, decompressedData);
}

TEST_F(ZlibDecompressTest, handlesDataLargerThanChunk) 
{
    size_t chunkSize = 65536; // Same as in the function
    size_t largeSize = chunkSize * 3 + 1000; // Multiple chunks plus some extra
    auto originalData = createRepeatingData("MULTIPLEBLOCKS", largeSize);
    auto compressedData = zlibCompress(originalData);
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(originalData, decompressedData);
}

// Test deterministic behavior
TEST_F(ZlibDecompressTest, producesDeterministicOutput) 
{
    auto originalData = stringToVector("Deterministic test data");
    auto compressedData = zlibCompress(originalData);
    
    auto result1 = decryptorUtils::zlibDecompress(compressedData);
    auto result2 = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(result1, result2);
    EXPECT_EQ(originalData, result1);
}

// Test with empty original data (edge case)
TEST_F(ZlibDecompressTest, handlesEmptyOriginalData) 
{
    std::vector<unsigned char> emptyData;
    
    // Note: zlibCompress returns empty for empty input
    auto compressedData = zlibCompress(stringToVector("x")); // Compress something first
    
    // Then test with actual empty data compression (if zlib supports it)
    z_stream stream {};
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    
    if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) == Z_OK) {
        std::vector<unsigned char> buffer(1024);
        stream.avail_in = 0;
        stream.next_in = nullptr;
        stream.avail_out = static_cast<uInt>(buffer.size());
        stream.next_out = buffer.data();
        
        int ret = deflate(&stream, Z_FINISH);
        if (ret == Z_STREAM_END) {
            size_t compressedSize = buffer.size() - stream.avail_out;
            std::vector<unsigned char> emptyCompressed(buffer.begin(), buffer.begin() + compressedSize);
            
            auto decompressed = decryptorUtils::zlibDecompress(emptyCompressed);
            EXPECT_TRUE(decompressed.empty());
        }
        deflateEnd(&stream);
    }
}


// Test with malformed zlib header
TEST_F(ZlibDecompressTest, throwsOnMalformedHeader) 
{
    std::vector<unsigned char> malformedData = {0x78, 0x9C}; // Valid start but incomplete
    auto extra = createRandomData(10); 
    malformedData.insert(malformedData.end(), extra.begin(), extra.end());
    
    EXPECT_THROW(decryptorUtils::zlibDecompress(malformedData), std::runtime_error);
}

// Performance test
TEST_F(ZlibDecompressTest, performanceTest) {
    auto originalData = createRepeatingData("PERFORMANCE_TEST_DATA", 10240); // 10KB
    auto compressedData = zlibCompress(originalData);
    
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto result = decryptorUtils::zlibDecompress(compressedData);
        // Prevent optimization
        volatile auto temp = result[0];
        (void)temp;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    EXPECT_LT(duration.count(), 5000) << "Zlib decompression should complete " 
                                      << iterations << " operations in reasonable time";
}

// Thread safety test
TEST_F(ZlibDecompressTest, threadSafetyTest) {
    auto originalData = stringToVector("Thread safety test data for zlib decompression");
    auto compressedData = zlibCompress(originalData);
    
    const int numThreads = 4;
    const int iterationsPerThread = 50;
    std::vector<std::thread> threads;
    std::atomic<int> successCount{0};
    
    for (int i = 0; i < numThreads; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < iterationsPerThread; ++j) {
                try {
                    auto result = decryptorUtils::zlibDecompress(compressedData);
                    if (result == originalData) {
                        successCount++;
                    }
                } catch (...) {
                    // Count exceptions as failures
                }
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(successCount.load(), numThreads * iterationsPerThread) 
        << "All decompression operations should succeed in multi-threaded environment";
}

// Test with various data patterns
TEST_F(ZlibDecompressTest, handlesVariousDataPatterns) {
    std::vector<std::string> patterns = {
        "AAAAAAAAAA",           // Highly repetitive
        "ABCDEFGHIJ",           // Sequential
        "A1B2C3D4E5",          // Mixed alphanumeric
        std::string("\x00\x01\x02\x03", 4),   // Binary sequence
        "The quick brown fox jumps over the lazy dog", // Natural text
    };
    
    for (const auto& pattern : patterns) {
        auto originalData = createRepeatingData(pattern, 1000);
        auto compressedData = zlibCompress(originalData);
        auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
        
        EXPECT_EQ(originalData, decompressedData) << "Failed for pattern: " << pattern;
    }
}

// Test edge case: single byte data
TEST_F(ZlibDecompressTest, handlesSingleByte) {
    std::vector<unsigned char> singleByte = {0x42};
    auto compressedData = zlibCompress(singleByte);
    
    auto decompressedData = decryptorUtils::zlibDecompress(compressedData);
    
    EXPECT_EQ(singleByte, decompressedData);
}