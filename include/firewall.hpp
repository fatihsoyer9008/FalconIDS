#pragma once

#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace netfalcon {

// Belirli bir esik asildiginda saldirgan IP'yi isletim sisteminin guvenlik
// duvari (iptables veya ufw) uzerinden otomatik engelleyen IPS modulu.
//
// Guvenlik onlemleri:
//   - Ozel (RFC 1918) ve loopback IP'ler ASLA engellenmez.
//   - Whitelist'teki IP'ler engellenmez (gateway, DNS, vb.).
//   - IP formati dogrulanir (komut enjeksiyonu onleme).
//   - Zaten engellenmis IP'ler tekrar engellenmez.
//
// Kullanim:
//   1. Nesneyi olustur (esik: kac alert sonrasi engellensin).
//   2. addToWhitelist() ile guvenli IP'leri ekle.
//   3. Her alert uretildiginde recordStrike(ip) cagir.
//   4. Strike sayisi esigi astiginda IP otomatik engellenir.
//
// NOT: iptables/ufw komutlari root yetkisi gerektirir.
//      FalconIDS zaten pcap icin root ile calistirilmak zorunda oldugundan
//      bu ek bir gereksinim degildir.
class FirewallBlocker {
public:
    // blockThreshold: Bir IP'den kac alert sonrasi engelleme uygulansin (varsayilan 3)
    explicit FirewallBlocker(int blockThreshold = 3);
    ~FirewallBlocker() = default;

    // Kopyalama engellenir.
    FirewallBlocker(const FirewallBlocker&) = delete;
    FirewallBlocker& operator=(const FirewallBlocker&) = delete;

    // ─── Yapilandirma ────────────────────────────────────────────────────

    // Whitelist'e IP ekler. Bu IP'ler asla engellenmez.
    // Ornek: gateway (192.168.1.1), DNS sunuculari (8.8.8.8), vb.
    void addToWhitelist(const std::string& ip);

    // Birden fazla IP'yi whitelist'e ekler.
    void addToWhitelist(const std::vector<std::string>& ips);

    // ─── Strike kaydi ve otomatik engelleme ──────────────────────────────

    // Bir IP icin strike (ihtar) kaydeder. Esik asilirsa IP otomatik engellenir.
    // Dondurulen deger: IP yeni engellendiyse true, aksi halde false.
    bool recordStrike(const std::string& ip);

    // ─── Dogrudan engelleme ──────────────────────────────────────────────

    // Bir IP'yi aninda engeller (strike esigini beklemeden).
    // Basarili olursa true doner.
    bool blockIp(const std::string& ip);

    // ─── Sorgulama ───────────────────────────────────────────────────────

    // IP zaten engellenmis mi?
    bool isBlocked(const std::string& ip) const;

    // IP whitelist'te mi?
    bool isWhitelisted(const std::string& ip) const;

    // Mevcut strike sayisini doner (0 eger kayit yoksa).
    int getStrikeCount(const std::string& ip) const;

    // Toplam engellenmis IP sayisi.
    int totalBlocked() const;

private:
    // Sistemde kullanilabilir guvenlik duvari aracini tespit eder.
    enum class FirewallTool { IPTABLES, UFW, NONE };
    FirewallTool detectTool() const;

    // Arac-bazli engelleme
    bool blockWithIptables(const std::string& ip);
    bool blockWithUfw(const std::string& ip);

    // IP formatini dogrular (komut enjeksiyonu onleme).
    // Sadece [0-9] ve '.' karakterlerine izin verir (IPv4).
    static bool isValidIpv4(const std::string& ip);

    // Ozel/loopback IP kontrolu
    static bool isPrivateIp(const std::string& ip);

    int blockThreshold_;
    FirewallTool tool_;

    std::set<std::string> blockedIps_;
    std::set<std::string> whitelist_;
    std::unordered_map<std::string, int> strikeCount_;
    mutable std::mutex mutex_;
};

}  // namespace netfalcon

