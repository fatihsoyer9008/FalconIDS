// parser.cpp icin birim testleri.
//
// Harici bir test framework'u kullanilmiyor (bagimliligi az tutmak icin):
// her kontrol CHECK() makrosuyla yapilir, hata sayisi biriktirilir ve
// main() sonunda hepsi basariliysa 0, degilse 1 doner. <cassert> tercih
// edilmedi cunku CMAKE_BUILD_TYPE=Release'de NDEBUG tanimliyken assert()
// derlemeden dusuyor — testlerimiz Release derlemesinde de calismali.

#include "packet_builder.hpp"
#include "parser.hpp"

#include <pcap.h>

#include <iostream>

using namespace netfalcon;
using namespace netfalcon_test;

namespace {

int g_failures = 0;

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

void testTcpSynParsedCorrectly() {
    std::cout << "test: TCP SYN paketi dogru ayristiriliyor\n";
    auto pkt = buildTcpPacket({192, 168, 1, 10}, {192, 168, 1, 20}, 51000, 80, TcpFlag::kSyn);

    ParsedPacket parsed;
    const bool ok = parsePacket(pkt.data(), pkt.size(), DLT_EN10MB, parsed);

    CHECK(ok);
    CHECK(parsed.protocol == Protocol::TCP);
    CHECK(parsed.srcIp == "192.168.1.10");
    CHECK(parsed.dstIp == "192.168.1.20");
    CHECK(parsed.srcPort == 51000);
    CHECK(parsed.dstPort == 80);
    CHECK(parsed.tcpFlags == TcpFlag::kSyn);
}

void testUdpParsedCorrectly() {
    std::cout << "test: UDP paketi dogru ayristiriliyor\n";
    auto pkt = buildUdpPacket({10, 0, 0, 5}, {10, 0, 0, 1}, 33445, 53, /*payloadLen=*/12);

    ParsedPacket parsed;
    const bool ok = parsePacket(pkt.data(), pkt.size(), DLT_EN10MB, parsed);

    CHECK(ok);
    CHECK(parsed.protocol == Protocol::UDP);
    CHECK(parsed.srcIp == "10.0.0.5");
    CHECK(parsed.dstIp == "10.0.0.1");
    CHECK(parsed.srcPort == 33445);
    CHECK(parsed.dstPort == 53);
    CHECK(parsed.payloadLen == 12);
}

void testTruncatedPacketIsRejected() {
    std::cout << "test: eksik/kirik paket reddediliyor\n";
    auto pkt = buildTcpPacket({10, 0, 0, 1}, {10, 0, 0, 2}, 1234, 22, TcpFlag::kSyn);
    pkt.resize(20);  // Ethernet + IPv4 basliginin bir kismi eksik birakildi

    ParsedPacket parsed;
    const bool ok = parsePacket(pkt.data(), pkt.size(), DLT_EN10MB, parsed);
    CHECK(!ok);
}

void testUnsupportedLinkTypeIsRejected() {
    std::cout << "test: desteklenmeyen link katmani tipi reddediliyor\n";
    auto pkt = buildTcpPacket({1, 2, 3, 4}, {5, 6, 7, 8}, 1, 2, TcpFlag::kAck);

    ParsedPacket parsed;
    const bool ok = parsePacket(pkt.data(), pkt.size(), /*linkType=*/9999, parsed);
    CHECK(!ok);
}

int main() {
    testTcpSynParsedCorrectly();
    testUdpParsedCorrectly();
    testTruncatedPacketIsRejected();
    testUnsupportedLinkTypeIsRejected();

    if (g_failures == 0) {
        std::cout << "\nTum parser testleri basarili.\n";
        return 0;
    }
    std::cerr << "\n" << g_failures << " kontrol basarisiz.\n";
    return 1;
}
