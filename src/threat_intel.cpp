#include "threat_intel.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <sstream>

namespace netfalcon {

// ─── libcurl write callback ──────────────────────────────────────────────────
// curl'den gelen HTTP yanit verilerini bir std::string'e yazar.
namespace {

std::size_t curlWriteCallback(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    auto* response = static_cast<std::string*>(userdata);
    const std::size_t totalBytes = size * nmemb;
    response->append(ptr, totalBytes);
    return totalBytes;
}

}  // namespace

// ─── Constructor / Destructor ────────────────────────────────────────────────

ThreatIntelChecker::ThreatIntelChecker(const std::string& apiKey,
                                       int scoreThreshold,
                                       std::chrono::seconds cacheTtl)
    : apiKey_(apiKey),
      scoreThreshold_(scoreThreshold),
      cacheTtl_(cacheTtl) {}

ThreatIntelChecker::~ThreatIntelChecker() {
    stop();
}

// ─── Thread yonetimi ─────────────────────────────────────────────────────────

void ThreatIntelChecker::start() {
    if (running_.exchange(true)) {
        return;  // Zaten calisiyor
    }
    workerThread_ = std::thread(&ThreatIntelChecker::workerLoop, this);
    std::cout << "[ThreatIntel] Arka plan kontrol thread'i baslatildi.\n";
}

void ThreatIntelChecker::stop() {
    if (!running_.exchange(false)) {
        return;  // Zaten durmus
    }
    queueCv_.notify_all();
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    std::cout << "[ThreatIntel] Arka plan kontrol thread'i durduruldu.\n";
}

// ─── Kuyruk ──────────────────────────────────────────────────────────────────

void ThreatIntelChecker::enqueueCheck(const std::string& ip) {
    // Ozel/loopback IP'leri kontrol etmeye gerek yok
    if (isPrivateIp(ip)) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        checkQueue_.push(ip);
    }
    queueCv_.notify_one();
}

// ─── Callback ────────────────────────────────────────────────────────────────

void ThreatIntelChecker::setThreatCallback(ThreatCallback callback) {
    std::lock_guard<std::mutex> lock(callbackMutex_);
    onThreatDetected_ = std::move(callback);
}

// ─── Ozel IP kontrolu ───────────────────────────────────────────────────────

bool ThreatIntelChecker::isPrivateIp(const std::string& ip) {
    // Hizli on-kontrol: ilk okteti parse et
    // 10.x.x.x, 127.x.x.x, 172.16-31.x.x, 192.168.x.x, 0.x.x.x
    if (ip.empty()) return true;

    // IPv4 adresinin ilk oktetini al
    unsigned int a = 0, b = 0;
    if (std::sscanf(ip.c_str(), "%u.%u", &a, &b) < 1) {
        return true;  // parse edilemiyorsa atla
    }

    if (a == 10 || a == 127 || a == 0) return true;
    if (a == 172 && b >= 16 && b <= 31) return true;
    if (a == 192 && b == 168) return true;

    return false;
}

// ─── Worker thread dongusu ───────────────────────────────────────────────────

void ThreatIntelChecker::workerLoop() {
    while (running_) {
        std::string ip;

        // Kuyruktan bir IP al (yoksa bekle)
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCv_.wait(lock, [this] { return !checkQueue_.empty() || !running_; });

            if (!running_) break;
            if (checkQueue_.empty()) continue;

            ip = std::move(checkQueue_.front());
            checkQueue_.pop();
        }

        // Cache kontrolu
        {
            std::lock_guard<std::mutex> lock(cacheMutex_);
            auto it = cache_.find(ip);
            if (it != cache_.end()) {
                const auto elapsed = std::chrono::steady_clock::now() - it->second.fetchedAt;
                if (elapsed < cacheTtl_) {
                    // Cache hala gecerli
                    if (it->second.isMalicious) {
                        std::lock_guard<std::mutex> cbLock(callbackMutex_);
                        if (onThreatDetected_) {
                            onThreatDetected_(ip, it->second.abuseScore, it->second.countryCode);
                        }
                    }
                    continue;
                }
                // Cache suresi dolmus, yeniden sorgula
                cache_.erase(it);
            }
        }

        // API sorgusu
        CachedResult result = queryApi(ip);

        // Sonucu cache'e ekle
        {
            std::lock_guard<std::mutex> lock(cacheMutex_);
            cache_[ip] = result;
        }

        // Zararli ise bildir
        if (result.isMalicious) {
            std::cout << "[THREAT] Zararli IP tespit edildi: " << ip
                      << " (skor: " << result.abuseScore
                      << ", ulke: " << result.countryCode << ")\n";

            std::lock_guard<std::mutex> cbLock(callbackMutex_);
            if (onThreatDetected_) {
                onThreatDetected_(ip, result.abuseScore, result.countryCode);
            }
        }
    }
}

// ─── AbuseIPDB API sorgusu ───────────────────────────────────────────────────

ThreatIntelChecker::CachedResult ThreatIntelChecker::queryApi(const std::string& ip) {
    CachedResult result;
    result.fetchedAt = std::chrono::steady_clock::now();

    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        std::cerr << "[ThreatIntel] libcurl baslatilamadi.\n";
        return result;
    }

    // URL olustur: https://api.abuseipdb.com/api/v2/check?ipAddress=X.X.X.X&maxAgeInDays=90
    std::string url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip + "&maxAgeInDays=90";

    // HTTP baslik listesi: API anahtari ve kabul formati
    struct curl_slist* headers = nullptr;
    std::string keyHeader = "Key: " + apiKey_;
    headers = curl_slist_append(headers, keyHeader.c_str());
    headers = curl_slist_append(headers, "Accept: application/json");

    std::string responseBody;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);          // 10 saniye timeout
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);    // 5 saniye baglanti timeout
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);    // Yonlendirmeleri takip et

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        std::cerr << "[ThreatIntel] API istegi basarisiz (" << ip << "): "
                  << curl_easy_strerror(res) << "\n";
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return result;
    }

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (httpCode != 200) {
        std::cerr << "[ThreatIntel] API HTTP hata kodu (" << ip << "): " << httpCode << "\n";
        if (httpCode == 429) {
            std::cerr << "[ThreatIntel] Rate limit asildi! Cache TTL'yi artirmayi deneyin.\n";
        }
        return result;
    }

    // JSON parse
    try {
        auto json = nlohmann::json::parse(responseBody);
        const auto& data = json["data"];

        result.abuseScore = data.value("abuseConfidenceScore", 0);
        result.countryCode = data.value("countryCode", "??");
        result.isMalicious = (result.abuseScore >= scoreThreshold_);

    } catch (const nlohmann::json::exception& e) {
        std::cerr << "[ThreatIntel] JSON parse hatasi (" << ip << "): " << e.what() << "\n";
    }

    return result;
}

}  // namespace netfalcon
