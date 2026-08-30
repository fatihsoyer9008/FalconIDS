#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace netfalcon {

// TCP bayrak (flag) bit degerleri — ParsedPacket::tcpFlags alaniyla birlikte kullanilir.
namespace TcpFlag {
constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kPsh = 0x08;
constexpr uint8_t kAck = 0x10;
constexpr uint8_t kUrg = 0x20;
}  // namespace TcpFlag

enum class Protocol { TCP, UDP, ICMP, OTHER };

struct ParsedPacket {
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    Protocol protocol = Protocol::OTHER;
    uint8_t tcpFlags = 0;  // sadece protocol == TCP iken anlamli
    std::size_t payloadLen = 0;
};

// Ham paket byte'larini (link katmani dahil) ayristirip out'u doldurur.
// linkType, pcap_datalink() ile elde edilen DLT_* degeridir; farkli
// arayuz turlerinde (Ethernet, loopback, Linux "cooked") link-katmani
// basliginin boyutu degistigi icin gereklidir.
// IPv4 disi ya da eksik/bozuk paketlerde false doner.
bool parsePacket(const uint8_t* data, std::size_t len, int linkType, ParsedPacket& out);

}  // namespace netfalcon
