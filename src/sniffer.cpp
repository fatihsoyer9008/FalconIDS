#include "sniffer.hpp"

#include <iostream>

namespace netfalcon {

Sniffer::Sniffer(std::string interfaceName, int snapLen, int timeoutMs)
    : interfaceName_(std::move(interfaceName)),
      snapLen_(snapLen),
      timeoutMs_(timeoutMs),
      handle_(nullptr),
      running_(false) {}

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
    // TODO: parser.hpp ile entegre edilecek. Simdilik yakalanan paketin
    // boyutu basilarak yakalama hattinin calistigi dogrulaniyor.
    (void)packet;
    std::cout << "[Sniffer] paket yakalandi: " << header->len << " byte\n";
}

}  // namespace netfalcon
