#pragma once

#include "rules.hpp"

#include <pcap.h>

#include <atomic>
#include <string>

namespace netfalcon {

// Forward declaration — tam tanimlama icin ilgili header include edilmeli.
class ThreatIntelChecker;
class Notifier;
class FirewallBlocker;

// Belirtilen ag arayuzunu promiscuous modda acip paketleri yakalayan cekirdek sinif.
class Sniffer {
public:
    // threatIntel, notifier ve firewall nullptr olabilir; bu durumda ilgili modul devre disi kalir.
    explicit Sniffer(std::string interfaceName, int snapLen = 65535, int timeoutMs = 1000,
                     ThreatIntelChecker* threatIntel = nullptr,
                     Notifier* notifier = nullptr,
                     FirewallBlocker* firewall = nullptr);
    ~Sniffer();

    Sniffer(const Sniffer&) = delete;
    Sniffer& operator=(const Sniffer&) = delete;

    // Arayuzu promiscuous modda acar. Basarisiz olursa false doner.
    bool open();

    // Paketler stop() cagrilana kadar yakalanir (sonsuz dongu).
    void run();

    // Calisan yakalama dongusunu guvenli sekilde durdurur.
    void stop();

private:
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet);
    void handlePacket(const struct pcap_pkthdr* header, const u_char* packet);

    std::string interfaceName_;
    int snapLen_;
    int timeoutMs_;
    pcap_t* handle_;
    int linkType_;
    std::atomic<bool> running_;
    PortScanDetector portScanDetector_;
    SynFloodDetector synFloodDetector_;
    ThreatIntelChecker* threatIntel_;  // sahiplik almaz (non-owning pointer)
    Notifier* notifier_;               // sahiplik almaz (non-owning pointer)
    FirewallBlocker* firewall_;        // sahiplik almaz (non-owning pointer)
};

}  // namespace netfalcon
