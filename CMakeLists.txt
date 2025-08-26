cmake_minimum_required(VERSION 3.20)
project(WhatsappDbDecryptor VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
cmake_policy(SET CMP0091 NEW)

# Find Conan-generated packages
find_package(cpr CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(CLI11 CONFIG REQUIRED)
find_package(OpenSSL CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(gpsoauth-cpp CONFIG REQUIRED)
find_package(date REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Protobuf REQUIRED)
find_package(plog REQUIRED)

set(WABDD_PUBLIC_INCLUDE   ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(WABDD_PRIVATE_INCLUDE  ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(PROTO_DIR              ${CMAKE_CURRENT_SOURCE_DIR}/proto)



set(PROTO_FILES
    ${PROTO_DIR}/backupPrefix.proto
    ${PROTO_DIR}/C15IV.proto
    ${PROTO_DIR}/keyType.proto
    ${PROTO_DIR}/backupExpiry.proto
    ${PROTO_DIR}/C14Cipher.proto
)

add_library(wabdd_proto STATIC)
target_link_libraries(wabdd_proto PUBLIC protobuf::libprotobuf)
target_include_directories(wabdd_proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

protobuf_generate(
    TARGET wabdd_proto
    LANGUAGE cpp
    IMPORT_DIRS ${PROTO_DIR}     # <— this adds -I for protoc
    PROTOS ${PROTO_FILES}
)


# Define the static library
add_library(wabdd_core STATIC
        src/utils.cpp
        src/Crypt15Decryptor.cpp
        src/DecryptionManager.cpp
        src/Key15.cpp
        src/Mcrypt1Decryptor.cpp
       
)

target_include_directories(wabdd_core
        PUBLIC  ${WABDD_PUBLIC_INCLUDE}
        PRIVATE ${WABDD_PRIVATE_INCLUDE})

target_compile_definitions(wabdd_core PRIVATE WABDD_VERSION="${PROJECT_VERSION}")


target_link_libraries(wabdd_core
        PUBLIC
        cpr::cpr
        nlohmann_json::nlohmann_json
        OpenSSL::SSL
        OpenSSL::Crypto
        gpsoauth-cpp::gpsoauth-cpp
        CLI11::CLI11
        date::date
        ZLIB::ZLIB
        wabdd_proto
        plog::plog
)

add_executable(wabdd src/main.cpp
        src/logging.cpp)

target_include_directories(wabdd
        PRIVATE ${WABDD_PRIVATE_INCLUDE})

target_link_libraries(wabdd
        PRIVATE
        wabdd_core
)

###### GTEST

enable_testing()

add_executable(test_utils
        tests/test_utils.cpp
        tests/EncryptionLoopTest.cpp
        tests/FromHexTests.cpp
        tests/ISO8601Test.cpp
        tests/AesGcmTests.cpp
        tests/Base64DecodeTests.cpp
        tests/MetadataDecryptionTests.cpp
        tests/ReadBinaryFileTests.cpp
        tests/ReadTextFileTests.cpp
        tests/FileTimeConversionTests.cpp
        tests/MetadataInfoTests.cpp
        tests/HkdfDerivationTests.cpp
        tests/AesCbcDecryptTests.cpp
        tests/ZlibDecompressionTests.cpp
        include/FileEntry.h
        include/logging.h)

target_include_directories(test_utils PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(test_utils PRIVATE
        wabdd_core
        GTest::gtest
        GTest::gtest_main
        OpenSSL::Crypto
        gpsoauth-cpp::gpsoauth-cpp
)


include(GoogleTest)
gtest_discover_tests(test_utils)

# Installation rules
install(TARGETS wabdd_core
        EXPORT wabdd_targets
        ARCHIVE DESTINATION lib
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION include)

