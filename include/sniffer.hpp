#pragma once

#include <pcap.h>

#include <atomic>
#include <string>

namespace netfalcon {

// Belirtilen ag arayuzunu promiscuous modda acip paketleri yakalayan cekirdek sinif.
class Sniffer {
public:
    explicit Sniffer(std::string interfaceName, int snapLen = 65535, int timeoutMs = 1000);
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
    std::atomic<bool> running_;
};

}  // namespace netfalcon
