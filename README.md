<div align="center">

# Multi-Browser Password Extractor v2.1

**Educational & Research Project for Windows (Chromium-based browsers)**

![C++](https://img.shields.io/badge/C%2B%2B-17-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows-informational)
![Status](https://img.shields.io/badge/status-Research%20Project-orange)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

## overview

**Multi-Browser Password Extractor v2.1** is a Windows-based C++ research project that demonstrates how Chromium-based browsers store and protect saved credentials.

The tool:
- Reads browser login databases
- Retrieves the encrypted master key from *Local State*
- Uses **Windows DPAPI + AES-GCM** to decrypt saved passwords
- Exports results to a structured CSV file

> ⚠️ **This project is intended strictly for educational and research purposes.  
Use ONLY on systems you own or have explicit permission to test.**

---

## Supported Browsers

| Browser | Status |
|-------|--------|
| Google Chrome | ✅ |
| Microsoft Edge | ✅ |
| Brave Browser | ✅ |
| Opera | ✅ |
| Vivaldi | ✅ |
| Yandex Browser | ✅ |

Supports:
- `Default` profile  
- `Profile 1`, `Profile 2`, etc.

---

## Features

- DPAPI master key decryption
- AES-GCM password decryption (`v10` / `v11`)
- Multi-profile support
- QLite login database parsing
- CSV export (`browser_passwords.csv`)
- Automatic cleanup of temp files
- Fast & fully local execution

---

## Tech Stack

- **Language:** C++ (C++17)
- **Crypto:** Crypto++
- **Database:** SQLite3
- **JSON:** nlohmann/json
- **Platform:** Windows (WinAPI, DPAPI)

---

##  Output Example

```csv
ID,Browser,URL,Username,Password
0,Chrome,https://example.com,user@example.com,password123
1,Edge,https://site.com,admin,admin_pass
