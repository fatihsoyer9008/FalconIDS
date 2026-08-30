#include "sniffer.hpp"

#include "firewall.hpp"
#include "notifier.hpp"
#include "parser.hpp"
#include "threat_intel.hpp"

#include <iostream>

namespace netfalcon {

Sniffer::Sniffer(std::string interfaceName, int snapLen, int timeoutMs,
                 ThreatIntelChecker* threatIntel, Notifier* notifier,
                 FirewallBlocker* firewall)
    : interfaceName_(std::move(interfaceName)),
      snapLen_(snapLen),
      timeoutMs_(timeoutMs),
      handle_(nullptr),
      linkType_(-1),
      running_(false),
      threatIntel_(threatIntel),
      notifier_(notifier),
      firewall_(firewall) {}

Sniffer::~Sniffer() {
    if (handle_ != nullptr) {
        pcap_close(handle_);
    }
}

bool Sniffer::open() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1 -> promiscuous mode acik: sadece bu arayuze degil, ag segmentindeki
    // tum paketlere bakilir (IDS icin gerekli).
    handle_ = pcap_open_live(interfaceName_.c_str(), snapLen_, 1, timeoutMs_, errbuf);
    if (handle_ == nullptr) {
        std::cerr << "[Sniffer] arayuz acilamadi (" << interfaceName_ << "): " << errbuf << "\n";
        return false;
    }

    linkType_ = pcap_datalink(handle_);

    std::cout << "[Sniffer] " << interfaceName_ << " promiscuous modda dinleniyor.\n";
    return true;
}

void Sniffer::run() {
    if (handle_ == nullptr) {
        std::cerr << "[Sniffer] run() cagrilmadan once open() basariyla tamamlanmali.\n";
        return;
    }

    running_ = true;
    while (running_) {
        int result = pcap_dispatch(handle_, -1, &Sniffer::packetHandler, reinterpret_cast<u_char*>(this));
        if (result == PCAP_ERROR) {
            std::cerr << "[Sniffer] paket yakalama hatasi: " << pcap_geterr(handle_) << "\n";
            break;
        }
    }
}

void Sniffer::stop() {
    running_ = false;
    if (handle_ != nullptr) {
        pcap_breakloop(handle_);
    }
}

void Sniffer::packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet) {
    auto* self = reinterpret_cast<Sniffer*>(userData);
    self->handlePacket(header, packet);
}

void Sniffer::handlePacket(const struct pcap_pkthdr* header, const u_char* packet) {
    ParsedPacket parsed;
    if (!parsePacket(packet, header->caplen, linkType_, parsed)) {
        return;
    }

    // Tehdit istihbarati kontrolu (asenkron, non-blocking)
    if (threatIntel_ != nullptr) {
        threatIntel_->enqueueCheck(parsed.srcIp);
        threatIntel_->enqueueCheck(parsed.dstIp);
    }

    std::string alertMsg;
    if (portScanDetector_.onPacket(parsed, alertMsg)) {
        std::cout << alertMsg << "\n";

        // Bildirim gonder (asenkron, non-blocking)
        if (notifier_ != nullptr) {
            notifier_->sendAlert(alertMsg, "High");
        }

        // Saldirgan IP icin strike kaydet (esik asilirsa otomatik engellenir)
        if (firewall_ != nullptr) {
            firewall_->recordStrike(parsed.srcIp);
        }
    }

    std::string synAlertMsg;
    if (synFloodDetector_.onPacket(parsed, synAlertMsg)) {
        std::cout << synAlertMsg << "\n";

        if (notifier_ != nullptr) {
            notifier_->sendAlert(synAlertMsg, "Critical");
        }

        if (firewall_ != nullptr) {
            firewall_->recordStrike(parsed.srcIp);
        }
    }
}

}  // namespace netfalcon
