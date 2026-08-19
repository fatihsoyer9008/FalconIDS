#pragma once

#include "parser.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace netfalcon {

// Ayni kaynak IP'nin kisa bir zaman penceresi icinde birbirinden farkli
// coklu porta baglanmaya calismasini (klasik port taramasi) tespit eder.
class PortScanDetector {
public:
    explicit PortScanDetector(int distinctPortThreshold = 15,
                               std::chrono::seconds window = std::chrono::seconds(5));

    // Yeni bir paket geldiginde cagrilir. Esik asilirsa true doner ve
    // alertMsg insan-okunabilir bir uyari mesaji ile doldurulur.
    bool onPacket(const ParsedPacket& packet, std::string& alertMsg);

private:
    struct PortHit {
        uint16_t port;
        std::chrono::steady_clock::time_point time;
    };

    int distinctPortThreshold_;
    std::chrono::seconds window_;
    std::unordered_map<std::string, std::vector<PortHit>> hitsByIp_;
};

}  // namespace netfalcon
