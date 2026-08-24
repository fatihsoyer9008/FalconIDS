#include "firewall.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>

namespace netfalcon {

// ─── Constructor ─────────────────────────────────────────────────────────────

FirewallBlocker::FirewallBlocker(int blockThreshold)
    : blockThreshold_(blockThreshold), tool_(detectTool()) {

    switch (tool_) {
        case FirewallTool::UFW:
            std::cout << "[Firewall] Guvenlik duvari araci: ufw\n";
            break;
        case FirewallTool::IPTABLES:
            std::cout << "[Firewall] Guvenlik duvari araci: iptables\n";
            break;
        case FirewallTool::NONE:
            std::cerr << "[Firewall] UYARI: iptables veya ufw bulunamadi! "
                         "Otomatik engelleme devre disi.\n";
            break;
    }

    std::cout << "[Firewall] Engelleme esigi: " << blockThreshold_
              << " strike sonrasi otomatik engelleme.\n";
}

// ─── Firewall araci tespiti ──────────────────────────────────────────────────

FirewallBlocker::FirewallTool FirewallBlocker::detectTool() const {
    // Oncelik: ufw (kullanici-dostu) > iptables (dusuk seviye)
    // 'which' komutu aracin PATH'te olup olmadigini kontrol eder.
    if (std::system("which ufw > /dev/null 2>&1") == 0) {
        return FirewallTool::UFW;
    }
    if (std::system("which iptables > /dev/null 2>&1") == 0) {
        return FirewallTool::IPTABLES;
    }
    return FirewallTool::NONE;
}

// ─── Whitelist ───────────────────────────────────────────────────────────────

void FirewallBlocker::addToWhitelist(const std::string& ip) {
    std::lock_guard<std::mutex> lock(mutex_);
    whitelist_.insert(ip);
    std::cout << "[Firewall] Whitelist'e eklendi: " << ip << "\n";
}

void FirewallBlocker::addToWhitelist(const std::vector<std::string>& ips) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& ip : ips) {
        whitelist_.insert(ip);
        std::cout << "[Firewall] Whitelist'e eklendi: " << ip << "\n";
    }
}

// ─── Strike kaydi ve otomatik engelleme ──────────────────────────────────────

bool FirewallBlocker::recordStrike(const std::string& ip) {
    // Oncelikli kontroller (lock almadan yapilabilir olan statik kontroller)
    if (!isValidIpv4(ip) || isPrivateIp(ip)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    // Whitelist ve zaten engellenmis kontrolu
    if (whitelist_.count(ip) > 0 || blockedIps_.count(ip) > 0) {
        return false;
    }

    // Strike say
    int& strikes = strikeCount_[ip];
    ++strikes;

    if (strikes < blockThreshold_) {
        std::cout << "[Firewall] Strike " << strikes << "/" << blockThreshold_
                  << " — " << ip << "\n";
        return false;
    }

    // Esik asildi — engelle (lock icinden cikip blockIp cagirmak yerine
    // dogrudan arac fonksiyonlarini cagiralim ki mutex reentrant olmasin)
    std::cout << "[Firewall] Esik asildi (" << strikes << " strike) — "
              << ip << " engelleniyor...\n";

    bool success = false;
    switch (tool_) {
        case FirewallTool::UFW:
            success = blockWithUfw(ip);
            break;
        case FirewallTool::IPTABLES:
            success = blockWithIptables(ip);
            break;
        case FirewallTool::NONE:
            std::cerr << "[Firewall] Engelleme basarisiz: firewall araci bulunamadi.\n";
            return false;
    }

    if (success) {
        blockedIps_.insert(ip);
        strikeCount_.erase(ip);  // Engellenince strike sifirla
        std::cout << "[BLOCKED] " << ip << " basariyla engellendi. "
                  << "Toplam engellenen: " << blockedIps_.size() << "\n";
    }

    return success;
}

// ─── Dogrudan engelleme ──────────────────────────────────────────────────────

bool FirewallBlocker::blockIp(const std::string& ip) {
    if (!isValidIpv4(ip)) {
        std::cerr << "[Firewall] Gecersiz IP formati: " << ip << "\n";
        return false;
    }
    if (isPrivateIp(ip)) {
        std::cerr << "[Firewall] Ozel IP engellenmez: " << ip << "\n";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    if (whitelist_.count(ip) > 0) {
        std::cerr << "[Firewall] Whitelist'teki IP engellenmez: " << ip << "\n";
        return false;
    }
    if (blockedIps_.count(ip) > 0) {
        return false;  // Zaten engelli
    }

    bool success = false;
    switch (tool_) {
        case FirewallTool::UFW:
            success = blockWithUfw(ip);
            break;
        case FirewallTool::IPTABLES:
            success = blockWithIptables(ip);
            break;
        case FirewallTool::NONE:
            std::cerr << "[Firewall] Engelleme basarisiz: firewall araci bulunamadi.\n";
            return false;
    }

    if (success) {
        blockedIps_.insert(ip);
        strikeCount_.erase(ip);
        std::cout << "[BLOCKED] " << ip << " basariyla engellendi. "
                  << "Toplam engellenen: " << blockedIps_.size() << "\n";
    }

    return success;
}

// ─── Sorgulama ───────────────────────────────────────────────────────────────

bool FirewallBlocker::isBlocked(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return blockedIps_.count(ip) > 0;
}

bool FirewallBlocker::isWhitelisted(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return whitelist_.count(ip) > 0;
}

int FirewallBlocker::getStrikeCount(const std::string& ip) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = strikeCount_.find(ip);
    return it != strikeCount_.end() ? it->second : 0;
}

int FirewallBlocker::totalBlocked() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int>(blockedIps_.size());
}

// ─── iptables ile engelleme ──────────────────────────────────────────────────

bool FirewallBlocker::blockWithIptables(const std::string& ip) {
    // iptables -C: Kural zaten var mi kontrol et (duplikasyon onleme)
    std::string checkCmd = "iptables -C INPUT -s " + ip + " -j DROP 2>/dev/null";
    if (std::system(checkCmd.c_str()) == 0) {
        // Kural zaten mevcut
        return true;
    }

    // iptables -I INPUT 1: Zincirin basina ekle (oncelik icin)
    std::string blockCmd = "iptables -I INPUT 1 -s " + ip + " -j DROP";
    int ret = std::system(blockCmd.c_str());

    if (ret != 0) {
        std::cerr << "[Firewall] iptables komutu basarisiz (exit: " << ret
                  << "): " << blockCmd << "\n";
        return false;
    }

    return true;
}

// ─── ufw ile engelleme ───────────────────────────────────────────────────────

bool FirewallBlocker::blockWithUfw(const std::string& ip) {
    // 'ufw insert 1 deny from <IP>' — kural listesinin basina ekler
    std::string blockCmd = "ufw insert 1 deny from " + ip + " 2>/dev/null";
    int ret = std::system(blockCmd.c_str());

    if (ret != 0) {
        std::cerr << "[Firewall] ufw komutu basarisiz (exit: " << ret
                  << "): " << blockCmd << "\n";
        return false;
    }

    return true;
}

// ─── IP dogrulama (komut enjeksiyonu onleme) ─────────────────────────────────

bool FirewallBlocker::isValidIpv4(const std::string& ip) {
    if (ip.empty() || ip.size() > 15) return false;  // max "255.255.255.255"

    // Sadece rakam ve nokta karakterine izin ver
    for (char c : ip) {
        if (c != '.' && (c < '0' || c > '9')) {
            return false;
        }
    }

    // 4 oktet kontrolu
    std::istringstream stream(ip);
    std::string octet;
    int count = 0;

    while (std::getline(stream, octet, '.')) {
        if (octet.empty() || octet.size() > 3) return false;
        int val = std::stoi(octet);
        if (val < 0 || val > 255) return false;
        ++count;
    }

    return count == 4;
}

// ─── Ozel IP kontrolu ───────────────────────────────────────────────────────

bool FirewallBlocker::isPrivateIp(const std::string& ip) {
    if (!isValidIpv4(ip)) return true;  // Gecersiz IP'yi de "ozel" say (engelleme)

    unsigned int a = 0, b = 0;
    if (std::sscanf(ip.c_str(), "%u.%u", &a, &b) < 1) {
        return true;
    }

    if (a == 10 || a == 127 || a == 0) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;

    return false;
}

}  // namespace netfalcon

