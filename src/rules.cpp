#include "rules.hpp"

#include <algorithm>
#include <set>
#include <sstream>

namespace netfalcon {

PortScanDetector::PortScanDetector(int distinctPortThreshold, std::chrono::seconds window)
    : distinctPortThreshold_(distinctPortThreshold), window_(window) {}

bool PortScanDetector::onPacket(const ParsedPacket& packet, std::string& alertMsg) {
    if (packet.protocol != Protocol::TCP && packet.protocol != Protocol::UDP) {
        return false;
    }

    const auto now = std::chrono::steady_clock::now();
    auto& hits = hitsByIp_[packet.srcIp];
    hits.push_back(PortHit{packet.dstPort, now});

    // Pencere disina cikan eski kayitlari at.
    hits.erase(std::remove_if(hits.begin(), hits.end(),
                               [&](const PortHit& hit) { return now - hit.time > window_; }),
               hits.end());

    std::set<uint16_t> distinctPorts;
    for (const auto& hit : hits) {
        distinctPorts.insert(hit.port);
    }

    if (static_cast<int>(distinctPorts.size()) < distinctPortThreshold_) {
        return false;
    }

    std::ostringstream oss;
    oss << "[ALERT] Olasi port taramasi: " << packet.srcIp << " son " << window_.count()
        << " saniyede " << distinctPorts.size() << " farkli porta eristi (esik: "
        << distinctPortThreshold_ << ")";
    alertMsg = oss.str();

    // Ayni uyariyi her paket icin tekrar tekrar basmamak icin gecmisi sifirla.
    hits.clear();
    return true;
}

}  // namespace netfalcon
