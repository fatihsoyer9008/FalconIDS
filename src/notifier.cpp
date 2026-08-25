#include "notifier.hpp"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace netfalcon {

// ─── libcurl write callback (yaniti yutmak icin) ─────────────────────────────
namespace {

std::size_t discardResponse(char* /*ptr*/, std::size_t size, std::size_t nmemb, void* /*userdata*/) {
    return size * nmemb;
}

// Severity degerine gore Discord embed rengi (decimal)
int severityColor(const std::string& severity) {
    if (severity == "Critical") return 10038562;  // koyu kirmizi  #993322
    if (severity == "High")     return 15158332;  // kirmizi       #E74C3C
    if (severity == "Medium")   return 15105570;  // turuncu       #E67E22
    if (severity == "Low")      return 3447003;   // yesil         #349B0B
    return 9807270;                                // gri (varsayilan) #959E9E
}

// Severity degerine gore emoji
std::string severityEmoji(const std::string& severity) {
    if (severity == "Critical") return "\xF0\x9F\x94\xB4";  // 🔴
    if (severity == "High")     return "\xF0\x9F\x9F\xA0";  // 🟠
    if (severity == "Medium")   return "\xF0\x9F\x9F\xA1";  // 🟡
    if (severity == "Low")      return "\xF0\x9F\x9F\xA2";  // 🟢
    return "\xE2\x9A\xAA";                                    // ⚪
}

// Simdi'nin insan-okunabilir zaman damgasi
std::string currentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &time);
#else
    localtime_r(&time, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

}  // namespace

// ─── Constructor / Destructor ────────────────────────────────────────────────

Notifier::Notifier() = default;

Notifier::~Notifier() {
    stop();
}

// ─── Kanal yapilandirmasi ────────────────────────────────────────────────────

void Notifier::configureDiscord(const std::string& webhookUrl) {
    discordWebhookUrl_ = webhookUrl;
    if (!webhookUrl.empty()) {
        std::cout << "[Notifier] Discord bildirimi yapilandirildi.\n";
    }
}

void Notifier::configureTelegram(const std::string& botToken, const std::string& chatId) {
    telegramBotToken_ = botToken;
    telegramChatId_ = chatId;
    if (!botToken.empty() && !chatId.empty()) {
        std::cout << "[Notifier] Telegram bildirimi yapilandirildi.\n";
    }
}

bool Notifier::isConfigured() const {
    bool discordOk = !discordWebhookUrl_.empty();
    bool telegramOk = !telegramBotToken_.empty() && !telegramChatId_.empty();
    return discordOk || telegramOk;
}

// ─── Thread yonetimi ─────────────────────────────────────────────────────────

void Notifier::start() {
    if (!isConfigured()) {
        std::cout << "[Notifier] Hicbir bildirim kanali yapilandirilmamis — baslatilmiyor.\n";
        return;
    }
    if (running_.exchange(true)) {
        return;  // Zaten calisiyor
    }
    workerThread_ = std::thread(&Notifier::workerLoop, this);
    std::cout << "[Notifier] Bildirim thread'i baslatildi.\n";
}

void Notifier::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    queueCv_.notify_all();
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    std::cout << "[Notifier] Bildirim thread'i durduruldu.\n";
}

// ─── Alert gonderme ──────────────────────────────────────────────────────────

void Notifier::sendAlert(const std::string& message, const std::string& severity) {
    if (!running_) return;

    AlertItem item;
    item.message = message;
    item.severity = severity;
    item.timestamp = std::chrono::steady_clock::now();

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        alertQueue_.push(std::move(item));
    }
    queueCv_.notify_one();
}

// ─── Worker thread dongusu ───────────────────────────────────────────────────

void Notifier::workerLoop() {
    while (running_) {
        AlertItem alert;

        // Kuyruktan bir alert al (yoksa bekle)
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueCv_.wait(lock, [this] { return !alertQueue_.empty() || !running_; });

            if (!running_) break;
            if (alertQueue_.empty()) continue;

            alert = std::move(alertQueue_.front());
            alertQueue_.pop();
        }

        // Rate limiting kontrolu
        if (isRateLimited(alert.message)) {
            continue;
        }

        // Yapilandirilmis kanallara gonder
        if (!discordWebhookUrl_.empty()) {
            sendToDiscord(alert);
        }
        if (!telegramBotToken_.empty() && !telegramChatId_.empty()) {
            sendToTelegram(alert);
        }
    }
}

// ─── Rate limiting ───────────────────────────────────────────────────────────

bool Notifier::isRateLimited(const std::string& message) {
    std::lock_guard<std::mutex> lock(rateMutex_);
    auto now = std::chrono::steady_clock::now();
    auto it = lastSentByContent_.find(message);

    if (it != lastSentByContent_.end()) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second);
        if (elapsed.count() < kRateLimitSeconds) {
            return true;  // Bu mesaj henuz rate limit penceresi icinde
        }
    }

    lastSentByContent_[message] = now;

    // Bellek tasmasini onlemek icin eski kayitlari temizle (1000'den fazla birikirse)
    if (lastSentByContent_.size() > 1000) {
        for (auto iter = lastSentByContent_.begin(); iter != lastSentByContent_.end();) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - iter->second);
            if (age.count() > kRateLimitSeconds * 2) {
                iter = lastSentByContent_.erase(iter);
            } else {
                ++iter;
            }
        }
    }

    return false;
}

// ─── Discord gonderim ────────────────────────────────────────────────────────

void Notifier::sendToDiscord(const AlertItem& alert) {
    // Discord Webhook Embed formati
    nlohmann::json embed;
    embed["title"] = severityEmoji(alert.severity) + " FalconIDS Alert";
    embed["description"] = alert.message;
    embed["color"] = severityColor(alert.severity);
    embed["fields"] = nlohmann::json::array({
        {{"name", "Severity"}, {"value", alert.severity}, {"inline", true}},
        {{"name", "Time"},     {"value", currentTimestamp()}, {"inline", true}}
    });
    embed["footer"] = {{"text", "FalconIDS Threat Detection System"}};

    nlohmann::json payload;
    payload["content"] = nullptr;
    payload["embeds"] = nlohmann::json::array({embed});

    httpPost(discordWebhookUrl_, payload.dump(), "Discord");
}

// ─── Telegram gonderim ──────────────────────────────────────────────────────

void Notifier::sendToTelegram(const AlertItem& alert) {
    std::string emoji = severityEmoji(alert.severity);

    // Telegram mesaj metni (HTML parse_mode)
    std::ostringstream text;
    text << emoji << " <b>FalconIDS Alert</b>\n\n"
         << alert.message << "\n\n"
         << "<b>Severity:</b> " << alert.severity << "\n"
         << "<b>Time:</b> " << currentTimestamp();

    nlohmann::json payload;
    payload["chat_id"] = telegramChatId_;
    payload["text"] = text.str();
    payload["parse_mode"] = "HTML";
    payload["disable_web_page_preview"] = true;

    std::string url = "https://api.telegram.org/bot" + telegramBotToken_ + "/sendMessage";
    httpPost(url, payload.dump(), "Telegram");
}

// ─── HTTP POST (libcurl) ─────────────────────────────────────────────────────

bool Notifier::httpPost(const std::string& url, const std::string& jsonPayload,
                        const std::string& channelName) {
    CURL* curl = curl_easy_init();
    if (curl == nullptr) {
        std::cerr << "[Notifier] libcurl baslatilamadi (" << channelName << ").\n";
        return false;
    }

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonPayload.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discardResponse);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);

    bool success = true;
    if (res != CURLE_OK) {
        std::cerr << "[Notifier] " << channelName << " gonderilemedi: "
                  << curl_easy_strerror(res) << "\n";
        success = false;
    } else {
        long httpCode = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
        if (httpCode >= 200 && httpCode < 300) {
            std::cout << "[Notifier] " << channelName << " bildirimi gonderildi.\n";
        } else {
            std::cerr << "[Notifier] " << channelName << " HTTP hata: " << httpCode << "\n";
            success = false;
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

}  // namespace netfalcon
