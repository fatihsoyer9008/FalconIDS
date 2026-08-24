#include "firewall.hpp"
#include "notifier.hpp"
#include "sniffer.hpp"
#include "threat_intel.hpp"

#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

netfalcon::Sniffer* g_activeSniffer = nullptr;
netfalcon::ThreatIntelChecker* g_threatIntel = nullptr;
netfalcon::Notifier* g_notifier = nullptr;

void handleInterrupt(int) {
    if (g_activeSniffer != nullptr) {
        g_activeSniffer->stop();
    }
    if (g_threatIntel != nullptr) {
        g_threatIntel->stop();
    }
    if (g_notifier != nullptr) {
        g_notifier->stop();
    }
}

// Virgul ile ayrilmis IP listesini parse eder.
// Ornek: "8.8.8.8,1.1.1.1,192.168.1.1" -> {"8.8.8.8", "1.1.1.1", "192.168.1.1"}
std::vector<std::string> parseIpList(const std::string& csv) {
    std::vector<std::string> result;
    std::istringstream stream(csv);
    std::string ip;
    while (std::getline(stream, ip, ',')) {
        // Bosluk temizle
        ip.erase(0, ip.find_first_not_of(" \t"));
        ip.erase(ip.find_last_not_of(" \t") + 1);
        if (!ip.empty()) {
            result.push_back(ip);
        }
    }
    return result;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Kullanim: " << argv[0] << " <ag-arayuzu>\n";
        std::cerr << "Ornek:    " << argv[0] << " eth0\n";
        return 1;
    }

    // ─── Bildirimler (opsiyonel) ─────────────────────────────────────────
    auto notifier = std::make_unique<netfalcon::Notifier>();

    const char* discordUrl = std::getenv("DISCORD_WEBHOOK_URL");
    if (discordUrl != nullptr && discordUrl[0] != '\0') {
        notifier->configureDiscord(discordUrl);
    }

    const char* tgToken = std::getenv("TELEGRAM_BOT_TOKEN");
    const char* tgChatId = std::getenv("TELEGRAM_CHAT_ID");
    if (tgToken != nullptr && tgToken[0] != '\0' &&
        tgChatId != nullptr && tgChatId[0] != '\0') {
        notifier->configureTelegram(tgToken, tgChatId);
    }

    if (notifier->isConfigured()) {
        notifier->start();
        g_notifier = notifier.get();
        std::cout << "[FalconIDS] Bildirim modulu aktif.\n";
    } else {
        std::cout << "[FalconIDS] Bildirim kanali yapilandirilmamis — bildirimler devre disi.\n";
        std::cout << "[FalconIDS] Discord: export DISCORD_WEBHOOK_URL=\"https://discord.com/api/webhooks/...\"\n";
        std::cout << "[FalconIDS] Telegram: export TELEGRAM_BOT_TOKEN=\"...\" TELEGRAM_CHAT_ID=\"...\"\n";
    }

    // ─── Firewall / IPS (opsiyonel) ──────────────────────────────────────
    // FALCON_IPS_ENABLED=1 ile aktiflestirilir.
    std::unique_ptr<netfalcon::FirewallBlocker> firewall;
    const char* ipsEnabled = std::getenv("FALCON_IPS_ENABLED");
    if (ipsEnabled != nullptr && std::string(ipsEnabled) == "1") {
        // Engelleme esigi (varsayilan 3)
        int threshold = 3;
        const char* thresholdEnv = std::getenv("FALCON_BLOCK_THRESHOLD");
        if (thresholdEnv != nullptr && thresholdEnv[0] != '\0') {
            threshold = std::atoi(thresholdEnv);
            if (threshold < 1) threshold = 3;
        }

        firewall = std::make_unique<netfalcon::FirewallBlocker>(threshold);

        // Whitelist
        const char* whitelistEnv = std::getenv("FALCON_WHITELIST");
        if (whitelistEnv != nullptr && whitelistEnv[0] != '\0') {
            auto ips = parseIpList(whitelistEnv);
            firewall->addToWhitelist(ips);
        }

        std::cout << "[FalconIDS] IPS modulu aktif — otomatik engelleme etkin.\n";
    } else {
        std::cout << "[FalconIDS] IPS devre disi. Aktiflestirmek icin: export FALCON_IPS_ENABLED=1\n";
    }

    // ─── Threat Intelligence (opsiyonel) ─────────────────────────────────
    std::unique_ptr<netfalcon::ThreatIntelChecker> threatIntel;
    const char* apiKey = std::getenv("ABUSEIPDB_API_KEY");
    if (apiKey != nullptr && apiKey[0] != '\0') {
        threatIntel = std::make_unique<netfalcon::ThreatIntelChecker>(apiKey);

        // Zararli IP tespit edildiginde: konsol + bildirim + firewall
        netfalcon::Notifier* notifierPtr = notifier->isConfigured() ? notifier.get() : nullptr;
        netfalcon::FirewallBlocker* firewallPtr = firewall.get();
        threatIntel->setThreatCallback(
            [notifierPtr, firewallPtr](const std::string& ip, int score, const std::string& country) {
                std::ostringstream oss;
                oss << "[THREAT-ALERT] Zararli IP: " << ip
                    << " | Skor: " << score
                    << " | Ulke: " << country;
                std::cout << oss.str() << "\n";

                // Bildirim gonder
                if (notifierPtr != nullptr) {
                    notifierPtr->sendAlert(oss.str(), score >= 80 ? "Critical" : "High");
                }

                // Yuksek skorlu IP'leri aninda engelle (strike bekleme)
                if (firewallPtr != nullptr && score >= 80) {
                    firewallPtr->blockIp(ip);
                } else if (firewallPtr != nullptr) {
                    firewallPtr->recordStrike(ip);
                }
            });

        threatIntel->start();
        g_threatIntel = threatIntel.get();
        std::cout << "[FalconIDS] Threat Intelligence modulu aktif (AbuseIPDB).\n";
    } else {
        std::cout << "[FalconIDS] ABUSEIPDB_API_KEY ayarlanmamis — tehdit istihbarati devre disi.\n";
        std::cout << "[FalconIDS] Aktiflestirmek icin: export ABUSEIPDB_API_KEY=\"sizin_api_anahtariniz\"\n";
    }

    // ─── Sniffer ─────────────────────────────────────────────────────────
    netfalcon::Sniffer sniffer(argv[1], 65535, 1000,
                                threatIntel.get(),
                                notifier->isConfigured() ? notifier.get() : nullptr,
                                firewall.get());
    g_activeSniffer = &sniffer;
    std::signal(SIGINT, handleInterrupt);

    if (!sniffer.open()) {
        return 1;
    }

    std::cout << "\n[FalconIDS] === Sistem hazir. Dinleme basliyor... ===\n\n";
    sniffer.run();

    // Temiz cikis
    if (threatIntel) {
        threatIntel->stop();
    }
    if (notifier->isConfigured()) {
        notifier->stop();
    }

    std::cout << "\n[FalconIDS] Kapatiliyor.\n";
    if (firewall) {
        std::cout << "[FalconIDS] Toplam engellenen IP: " << firewall->totalBlocked() << "\n";
    }

    return 0;
}
