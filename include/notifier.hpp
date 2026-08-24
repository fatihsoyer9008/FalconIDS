#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>

namespace netfalcon {

// Kritik seviyedeki saldiri/anomali tespitlerinde Discord ve/veya Telegram
// uzerinden anlik bildirim gonderen modul.
//
// Kullanim:
//   1. Nesneyi olustur.
//   2. configureDiscord() ve/veya configureTelegram() ile kanallari ayarla.
//   3. start() ile arka plan worker thread'ini baslat.
//   4. Alert uretildiginde sendAlert() cagir (non-blocking).
//   5. Program kapanirken stop() ile thread'i durdur.
//
// Rate limiting: Ayni mesaj icerigi 60 saniye icinde tekrar gonderilmez
// (flood onleme). Farkli mesajlar ayri ayri rate-limit'lenir.
class Notifier {
public:
    Notifier();
    ~Notifier();

    // Kopyalama/tasima engellenir — tekil kaynak yonetimi (thread).
    Notifier(const Notifier&) = delete;
    Notifier& operator=(const Notifier&) = delete;

    // ─── Kanal yapilandirmasi ────────────────────────────────────────────

    // Discord Webhook URL'si. Bos string verilirse Discord devre disi kalir.
    // Webhook olusturma: Discord Sunucu Ayarlari > Entegrasyonlar > Webhooks
    void configureDiscord(const std::string& webhookUrl);

    // Telegram Bot Token ve Chat ID. Ikisi de verilmezse Telegram devre disi.
    // Bot olusturma: @BotFather > /newbot
    // Chat ID bulma: Bot'a mesaj at, https://api.telegram.org/bot<TOKEN>/getUpdates
    void configureTelegram(const std::string& botToken, const std::string& chatId);

    // ─── Thread yonetimi ─────────────────────────────────────────────────

    void start();
    void stop();

    // ─── Alert gonderme ──────────────────────────────────────────────────

    // Bildirim kuyuruguna alert ekler. Non-blocking.
    // severity: "Low", "Medium", "High", "Critical"
    // Sadece yapilandirilmis kanallara gonderir.
    void sendAlert(const std::string& message, const std::string& severity = "High");

    // En az bir kanal yapilandirilmis mi?
    bool isConfigured() const;

private:
    struct AlertItem {
        std::string message;
        std::string severity;
        std::chrono::steady_clock::time_point timestamp;
    };

    // Worker thread dongusu
    void workerLoop();

    // Kanal-bazli gonderim
    void sendToDiscord(const AlertItem& alert);
    void sendToTelegram(const AlertItem& alert);

    // HTTP POST istegi (libcurl ile)
    bool httpPost(const std::string& url, const std::string& jsonPayload,
                  const std::string& channelName);

    // Rate limiting kontrolu — ayni mesaj son 60 sn icinde gonderilmis mi?
    bool isRateLimited(const std::string& message);

    // ─── Discord ─────────────────────────────────────────────────────────
    std::string discordWebhookUrl_;

    // ─── Telegram ────────────────────────────────────────────────────────
    std::string telegramBotToken_;
    std::string telegramChatId_;

    // ─── Rate limiting ───────────────────────────────────────────────────
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> lastSentByContent_;
    std::mutex rateMutex_;
    static constexpr int kRateLimitSeconds = 60;

    // ─── Is kuyrugu ──────────────────────────────────────────────────────
    std::queue<AlertItem> alertQueue_;
    std::mutex queueMutex_;
    std::condition_variable queueCv_;

    // ─── Worker thread ───────────────────────────────────────────────────
    std::thread workerThread_;
    std::atomic<bool> running_{false};
};

}  // namespace netfalcon
