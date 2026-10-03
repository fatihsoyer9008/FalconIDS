#pragma once

// Testler icin ham Ethernet + IPv4 + TCP/UDP paket byte'lari ureten yardimci
// fonksiyonlar. Gercek bir NIC/pcap olmadan parser.cpp'yi test edebilmek icin
// gerekli; checksum alanlari kasitli olarak 0 birakiliyor cunku parsePacket()
// checksum dogrulamasi yapmiyor.

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace netfalcon_test {

namespace detail {

inline void appendU16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

inline void appendU32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

inline void appendEthernetHeader(std::vector<uint8_t>& buf) {
    for (int i = 0; i < 6; ++i) buf.push_back(0xAA);  // dst mac (onemsiz)
    for (int i = 0; i < 6; ++i) buf.push_back(0xBB);  // src mac (onemsiz)
    appendU16(buf, 0x0800);                            // EtherType: IPv4
}

inline void appendIpv4Header(std::vector<uint8_t>& buf, std::array<uint8_t, 4> srcIp,
                              std::array<uint8_t, 4> dstIp, uint8_t protocol,
                              uint16_t payloadTotalLen) {
    const uint16_t totalLen = static_cast<uint16_t>(20 + payloadTotalLen);
    buf.push_back(0x45);          // version=4, IHL=5 (20 byte, secenek yok)
    buf.push_back(0x00);          // DSCP/ECN
    appendU16(buf, totalLen);     // toplam uzunluk
    appendU16(buf, 0x0000);       // identification
    appendU16(buf, 0x0000);       // flags + fragment offset
    buf.push_back(64);            // TTL
    buf.push_back(protocol);      // IPPROTO_TCP=6, IPPROTO_UDP=17
    appendU16(buf, 0x0000);       // checksum (parsePacket dogrulamiyor)
    for (uint8_t b : srcIp) buf.push_back(b);
    for (uint8_t b : dstIp) buf.push_back(b);
}

}  // namespace detail

// SYN/ACK gibi bayraklari test etmek icin tcpFlags dogrudan verilir
// (bkz. TcpFlag namespace'i, include/parser.hpp).
inline std::vector<uint8_t> buildTcpPacket(std::array<uint8_t, 4> srcIp,
                                            std::array<uint8_t, 4> dstIp, uint16_t srcPort,
                                            uint16_t dstPort, uint8_t tcpFlags,
                                            std::size_t payloadLen = 0) {
    std::vector<uint8_t> pkt;
    detail::appendEthernetHeader(pkt);

    const uint16_t tcpTotalLen = static_cast<uint16_t>(20 + payloadLen);
    detail::appendIpv4Header(pkt, srcIp, dstIp, /*protocol=*/6, tcpTotalLen);

    detail::appendU16(pkt, srcPort);
    detail::appendU16(pkt, dstPort);
    detail::appendU32(pkt, 0);   // sequence number
    detail::appendU32(pkt, 0);  // ack number
    pkt.push_back(0x50);        // data offset=5 (<<4), reserved=0
    pkt.push_back(tcpFlags);
    detail::appendU16(pkt, 0xFFFF);  // window
    detail::appendU16(pkt, 0x0000);  // checksum
    detail::appendU16(pkt, 0x0000);  // urgent pointer

    for (std::size_t i = 0; i < payloadLen; ++i) pkt.push_back('A');
    return pkt;
}

inline std::vector<uint8_t> buildUdpPacket(std::array<uint8_t, 4> srcIp,
                                            std::array<uint8_t, 4> dstIp, uint16_t srcPort,
                                            uint16_t dstPort, std::size_t payloadLen = 0) {
    std::vector<uint8_t> pkt;
    detail::appendEthernetHeader(pkt);

    const uint16_t udpTotalLen = static_cast<uint16_t>(8 + payloadLen);
    detail::appendIpv4Header(pkt, srcIp, dstIp, /*protocol=*/17, udpTotalLen);

    detail::appendU16(pkt, srcPort);
    detail::appendU16(pkt, dstPort);
    detail::appendU16(pkt, udpTotalLen);
    detail::appendU16(pkt, 0x0000);  // checksum

    for (std::size_t i = 0; i < payloadLen; ++i) pkt.push_back('A');
    return pkt;
}

}  // namespace netfalcon_test
