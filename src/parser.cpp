#include "parser.hpp"

#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>

namespace netfalcon {

namespace {

// pcap_datalink() degerine gore link-katmani basliginin byte cinsinden
// uzunlugunu doner; desteklenmeyen bir tur icin -1 doner.
int linkHeaderLength(int linkType) {
    switch (linkType) {
        case DLT_EN10MB:
            return 14;  // klasik Ethernet (dst mac + src mac + ethertype)
        case DLT_NULL:
            return 4;  // BSD/macOS loopback (protokol ailesi)
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            return 16;  // Linux "cooked capture" (ornegin "any" arayuzu)
#endif
        default:
            return -1;
    }
}

}  // namespace

bool parsePacket(const uint8_t* data, std::size_t len, int linkType, ParsedPacket& out) {
    const int linkHdrLen = linkHeaderLength(linkType);
    if (linkHdrLen < 0 || len < static_cast<std::size_t>(linkHdrLen) + sizeof(struct ip)) {
        return false;
    }

    const uint8_t* ipStart = data + linkHdrLen;
    const auto* ipHeader = reinterpret_cast<const struct ip*>(ipStart);

    if (ipHeader->ip_v != 4) {
        return false;  // simdilik sadece IPv4
    }

    const std::size_t ipHeaderLen = static_cast<std::size_t>(ipHeader->ip_hl) * 4;
    const std::size_t ipTotalLen = ntohs(ipHeader->ip_len);
    if (ipHeaderLen < sizeof(struct ip) ||
        len < static_cast<std::size_t>(linkHdrLen) + ipHeaderLen) {
        return false;
    }

    char srcBuf[INET_ADDRSTRLEN];
    char dstBuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipHeader->ip_src, srcBuf, sizeof(srcBuf));
    inet_ntop(AF_INET, &ipHeader->ip_dst, dstBuf, sizeof(dstBuf));
    out.srcIp = srcBuf;
    out.dstIp = dstBuf;

    const uint8_t* transportStart = ipStart + ipHeaderLen;
    const std::size_t availableAfterIp = len - linkHdrLen - ipHeaderLen;
    const std::size_t transportTotalLen =
        ipTotalLen > ipHeaderLen ? ipTotalLen - ipHeaderLen : availableAfterIp;

    switch (ipHeader->ip_p) {
        case IPPROTO_TCP: {
            if (availableAfterIp < sizeof(struct tcphdr)) {
                return false;
            }
            const auto* tcpHeader = reinterpret_cast<const struct tcphdr*>(transportStart);
            out.protocol = Protocol::TCP;
            out.srcPort = ntohs(tcpHeader->th_sport);
            out.dstPort = ntohs(tcpHeader->th_dport);
            out.tcpFlags = tcpHeader->th_flags;
            const std::size_t tcpHeaderLen = static_cast<std::size_t>(tcpHeader->th_off) * 4;
            out.payloadLen = transportTotalLen > tcpHeaderLen ? transportTotalLen - tcpHeaderLen : 0;
            break;
        }
        case IPPROTO_UDP: {
            if (availableAfterIp < sizeof(struct udphdr)) {
                return false;
            }
            const auto* udpHeader = reinterpret_cast<const struct udphdr*>(transportStart);
            out.protocol = Protocol::UDP;
            out.srcPort = ntohs(udpHeader->uh_sport);
            out.dstPort = ntohs(udpHeader->uh_dport);
            out.payloadLen = transportTotalLen > sizeof(struct udphdr)
                                  ? transportTotalLen - sizeof(struct udphdr)
                                  : 0;
            break;
        }
        case IPPROTO_ICMP:
            out.protocol = Protocol::ICMP;
            out.payloadLen = transportTotalLen;
            break;
        default:
            out.protocol = Protocol::OTHER;
            out.payloadLen = transportTotalLen;
            break;
    }

    return true;
}

}  // namespace netfalcon
