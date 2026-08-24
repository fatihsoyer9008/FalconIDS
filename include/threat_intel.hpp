#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>

namespace netfalcon {

// AbuseIPDB API'si uzerinden IP'lerin zararli olup olmadigini kontrol eden
// ve sonuclari bellek-ici cache'leyen modul.
//
// Kullanim:
//   1. Nesneyi olustur (API key, esik skor, cache suresi).
//   2. start() ile arka plan worker thread'ini baslat.
//   3. Her parse edilen pakette enqueueCheck(srcIp) cagir (non-blocking).
//   4. Zararli IP bulundugunda onThreatDetected callback'i tetiklenir.
//   5. Program kapanirken stop() ile thread'i durdur.
class ThreatIntelChecker {
public:
    // Zararli IP tespit edildiginde cagrilan callback tipi.
    // Parametreler: IP adresi, AbuseIPDB guven skoru (0-100), ulke kodu
    using ThreatCallback = std::function<void(const std::string& ip, int score, const std::string& country)>;

    // apiKey       : AbuseIPDB API anahtari
    // scoreThreshold: Bu deger ve uzerindeki skorlar "zararli" kabul edilir (varsayilan 50)
    // cacheTtl     : Sorgu sonuclarinin cache'te kalma suresi (varsayilan 1 saat)
    explicit ThreatIntelChecker(const std::string& apiKey,
                                 int scoreThreshold = 50,
                                 std::chrono::seconds cacheTtl = std::chrono::seconds(3600));
    ~ThreatIntelChecker();

    // Kopyalama/tasima engellenir — tekil kaynak yonetimi (thread).
    ThreatIntelChecker(const ThreatIntelChecker&) = delete;
    ThreatIntelChecker& operator=(const ThreatIntelChecker&) = delete;

    // Arka plan worker thread'ini baslatir.
    void start();

    // Worker thread'i guvenli sekilde durdurur (kuyrukta kalan isler atilir).
    void stop();

    // IP'yi kontrol kuyuruguna ekler. Non-blocking; paket yakalama dongusunu
    // bloklamaz. Ozel IP'ler (10.x, 172.16-31.x, 192.168.x, 127.x) otomatik atlanir.
    void enqueueCheck(const std::string& ip);

    // Zararli IP bulundugunda cagirilacak callback'i ayarlar.
    void setThreatCallback(ThreatCallback callback);

private:
    struct CachedResult {
        int abuseScore = 0;
        bool isMalicious = false;
        std::string countryCode;
        std::chrono::steady_clock::time_point fetchedAt;
    };

    // IP'nin ozel (RFC 1918 / loopback) olup olmadigini kontrol eder.
    static bool isPrivateIp(const std::string& ip);

    // AbuseIPDB API'sine HTTP GET istegi yapar ve sonucu doner.
    CachedResult queryApi(const std::string& ip);

    // Worker thread dongusu — kuyruktan IP alir, cache/API kontrol eder.
    void workerLoop();

    std::string apiKey_;
    int scoreThreshold_;
    std::chrono::seconds cacheTtl_;

    // --- Cache ---
    std::unordered_map<std::string, CachedResult> cache_;
    std::mutex cacheMutex_;

    // --- Is kuyrugu ---
    std::queue<std::string> checkQueue_;
    std::mutex queueMutex_;
    std::condition_variable queueCv_;

    // --- Worker thread ---
    std::thread workerThread_;
    std::atomic<bool> running_{false};

    // --- Callback ---
    ThreatCallback onThreatDetected_;
    std::mutex callbackMutex_;
};

}  // namespace netfalcon
