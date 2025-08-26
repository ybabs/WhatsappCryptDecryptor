//
// Created by daniel on 7/4/25.
//


#include <iostream>
#include "DecryptionManager.h"
#include "Crypt15Decryptor.h"
#include "Mcrypt1Decryptor.h"
#include <filesystem>

#include "logging.h"

int main(int, char**)
{
    try {
            logging::initLogging();
             // This is from End-to-end encryption key from whatsapp. For more info check out: https://faq.whatsapp.com/490592613091019
            const std::string keyHex = "yourencryptionKey";

        const std::filesystem::path crypt15File =
            "msgstore.db.crypt15";
        const std::filesystem::path mcrypt1File =
            "SomeFile.mcrypt1";

        const std::filesystem::path outDir = std::filesystem::path{"db_output"};

        Key15 key15(keyHex);
        std::error_code ec;
        std::filesystem::create_directories(outDir, ec);
        if (ec) {
            std::cerr << "Failed to create output directory " << outDir << ": "
                      << ec.message() << "\n";
            return 2;
        }

        bool anyAttempted = false;
        bool anySucceeded = false;

        // --- Decrypt crypt15 ---
        if (std::filesystem::exists(crypt15File)) {
            anyAttempted = true;
            Crypt15Decryptor c15;
            if (!c15.canDecrypt(crypt15File)) {
                std::cerr << "[skip] Not a .crypt15 file: " << crypt15File << "\n";
            } else {
                std::cout << "[info] Decrypting crypt15: " << crypt15File << "\n";
                if (c15.decrypt(crypt15File, key15, outDir)) {
                    anySucceeded = true;
                } else {
                    std::cerr << "[fail] Could not decrypt: " << crypt15File << "\n";
                }
            }
        } else {
            std::cerr << "[skip] crypt15 file missing: " << crypt15File << "\n";
        }

        // --- Decrypt mcrypt1 ---
        if (std::filesystem::exists(mcrypt1File)) {
            anyAttempted = true;
            Mcrypt1Decryptor mc1;
            if (!mc1.canDecrypt(mcrypt1File)) {
                std::cerr << "[skip] Not a .mcrypt1 file or missing metadata: "
                          << mcrypt1File << "\n";
            } else {
                std::cout << "[info] Decrypting mcrypt1: " << mcrypt1File << "\n";
                if (mc1.decrypt(mcrypt1File, key15, outDir)) {
                    anySucceeded = true;
                } else {
                    std::cerr << "[fail] Could not decrypt: " << mcrypt1File << "\n";
                }
            }
        } else {
            std::cerr << "[skip] mcrypt1 file missing: " << mcrypt1File << "\n";
        }

        if (!anyAttempted) {
            std::cerr << "No input files found.\n";
            return 2;
        }
        if (!anySucceeded) {
            std::cerr << "Decryption failed for all inputs.\n";
            return 3;
        }

        std::cout << "Done.\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 4;
    } catch (...) {
        std::cerr << "Unknown error\n";
        return 5;
    }
}
