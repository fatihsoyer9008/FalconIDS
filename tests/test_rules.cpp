// rules.cpp icin birim testleri (PortScanDetector, SynFloodDetector).
//
// Detector'lar gercek zamanli (std::chrono::steady_clock::now()) calistigi
// icin testler zaman pencerelerini bekleyerek dogrulamiyor; onun yerine
// esigin altinda/ustunde paket sayilari gonderip donen sonucu kontrol
// ediyoruz. Bkz. tests/test_parser.cpp icin CHECK() aciklamasi.

#include "parser.hpp"
#include "rules.hpp"

#include <iostream>
#include <string>

using namespace netfalcon;

namespace {

int g_failures = 0;

ParsedPacket makeTcpPacket(const std::string& srcIp, uint16_t dstPort, uint8_t tcpFlags) {
    ParsedPacket p;
    p.srcIp = srcIp;
    p.dstIp = "10.0.0.1";
    p.srcPort = 40000;
    p.dstPort = dstPort;
    p.protocol = Protocol::TCP;
    p.tcpFlags = tcpFlags;
    return p;
}

}  // namespace

#define CHECK(cond)                                                                     \
    do {                                                                                 \
        if (cond) {                                                                      \
            std::cout << "  [PASS] " << #cond << "\n";                                  \
        } else {                                                                         \
            std::cout << "  [FAIL] " << #cond << " (" << __FILE__ << ":" << __LINE__     \
                       << ")\n";                                                         \
            ++g_failures;                                                                \
        }                                                                                \
    } while (0)

void testPortScanTriggersAtThreshold() {
    std::cout << "test: PortScanDetector esikte tetikleniyor\n";
    PortScanDetector detector(/*distinctPortThreshold=*/5, std::chrono::seconds(5));
    std::string alertMsg;
    bool triggered = false;

    // 4 farkli port -> esigin altinda, tetiklenmemeli.
    for (uint16_t port = 1; port <= 4; ++port) {
        auto pkt = makeTcpPacket("203.0.113.9", port, TcpFlag::kSyn);
        triggered = detector.onPacket(pkt, alertMsg);
        CHECK(!triggered);
    }

    // 5. farkli port -> esik asildi, tetiklenmeli.
    auto pkt = makeTcpPacket("203.0.113.9", 5, TcpFlag::kSyn);
    triggered = detector.onPacket(pkt, alertMsg);
    CHECK(triggered);
    CHECK(alertMsg.find("203.0.113.9") != std::string::npos);
}

void testPortScanIgnoresSinglePortRepeats() {
    std::cout << "test: PortScanDetector tek porta tekrar erisimi tarama saymiyor\n";
    PortScanDetector detector(/*distinctPortThreshold=*/5, std::chrono::seconds(5));
    std::string alertMsg;

    // Ayni porta 10 kez baglanmak "tarama" degildir (farkli port sayisi hep 1).
    for (int i = 0; i < 10; ++i) {
        auto pkt = makeTcpPacket("198.51.100.7", /*dstPort=*/80, TcpFlag::kSyn);
        bool triggered = detector.onPacket(pkt, alertMsg);
        CHECK(!triggered);
    }
}

void testSynFloodTriggersAtThreshold() {
    std::cout << "test: SynFloodDetector esikte tetikleniyor\n";
    SynFloodDetector detector(/*synCountThreshold=*/10, std::chrono::seconds(5));
    std::string alertMsg;
    bool triggered = false;

    for (int i = 0; i < 9; ++i) {
        auto pkt = makeTcpPacket("192.0.2.55", /*dstPort=*/80, TcpFlag::kSyn);
        triggered = detector.onPacket(pkt, alertMsg);
        CHECK(!triggered);
    }

    auto pkt = makeTcpPacket("192.0.2.55", /*dstPort=*/80, TcpFlag::kSyn);
    triggered = detector.onPacket(pkt, alertMsg);
    CHECK(triggered);
    CHECK(alertMsg.find("SYN flood") != std::string::npos);
}

void testSynFloodIgnoresCompletedHandshakes() {
    std::cout << "test: SynFloodDetector SYN+ACK/ACK paketlerini yok sayiyor\n";
    SynFloodDetector detector(/*synCountThreshold=*/5, std::chrono::seconds(5));
    std::string alertMsg;

    // Normal el sikismalar: SYN+ACK ya da sadece ACK — "saf SYN" degil.
    for (int i = 0; i < 20; ++i) {
        auto pkt = makeTcpPacket("192.0.2.77", 443, TcpFlag::kSyn | TcpFlag::kAck);
        bool triggered = detector.onPacket(pkt, alertMsg);
        CHECK(!triggered);
    }
}

void testSynFloodIgnoresNonTcp() {
    std::cout << "test: SynFloodDetector TCP disi paketleri yok sayiyor\n";
    SynFloodDetector detector(/*synCountThreshold=*/1, std::chrono::seconds(5));
    std::string alertMsg;

    ParsedPacket udpPkt;
    udpPkt.srcIp = "192.0.2.88";
    udpPkt.protocol = Protocol::UDP;
    bool triggered = detector.onPacket(udpPkt, alertMsg);
    CHECK(!triggered);
}

int main() {
    testPortScanTriggersAtThreshold();
    testPortScanIgnoresSinglePortRepeats();
    testSynFloodTriggersAtThreshold();
    testSynFloodIgnoresCompletedHandshakes();
    testSynFloodIgnoresNonTcp();

    if (g_failures == 0) {
        std::cout << "\nTum rules testleri basarili.\n";
        return 0;
    }
    std::cerr << "\n" << g_failures << " kontrol basarisiz.\n";
    return 1;
}
