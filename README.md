# FalconIDS

[![CI](https://github.com/fatihsoyer9008/FalconIDS/actions/workflows/ci.yml/badge.svg)](https://github.com/fatihsoyer9008/FalconIDS/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

C++17 ve libpcap ile geliştirilen, performans odaklı bir ağ trafiği analiz (IDS/IPS) aracıdır. Ağ arayüzünü promiscuous modda dinler, geçen paketleri ayrıştırır, anomali kurallarıyla (port taraması, SYN flood) şüpheli trafiği tespit eder; isteğe bağlı olarak tehdit istihbaratı sorgular, gerçek zamanlı bildirim gönderir ve saldırgan IP'leri otomatik olarak engeller.

## Nasıl çalışır

```
  Ağ Arayüzü (promiscuous)
          │  libpcap
          ▼
   ┌─────────────┐      ┌─────────────┐      ┌────────────────────┐
   │   Sniffer   │ ───▶ │   Parser    │ ───▶ │  Rules / Detector   │
   │ sniffer.hpp │      │ parser.hpp  │      │     rules.hpp       │
   └─────────────┘      └─────────────┘      └──────────┬─────────┘
   ham paketi yakalar    Ethernet/IPv4/       PortScanDetector,             │ [ALERT]
   (sonsuz döngü)        TCP/UDP/ICMP         SynFloodDetector: zaman       ▼
                         başlıklarını         penceresinde anomali arar   ┌────────────────────┐
                         ayrıştırır                                       │ Notifier / Firewall │
                                                                           │ (opsiyonel)         │
                                                                           └──────────┬──────────┘
                                                                                       │
                                              ┌────────────────────────────────────────┘
                                              ▼
                     Discord/Telegram bildirimi  +  eşik aşılırsa iptables/ufw ile otomatik engelleme

  Ayrıca her kaynak/hedef IP, arka planda AbuseIPDB'ye (threat_intel.hpp)
  sorulur; itibar skoru yüksekse aynı akışa (bildirim + engelleme) girer.
```

Her paket şu aşamalardan geçer: **yakala → ayrıştır → kurala karşı değerlendir**. Bir kural tetiklenirse konsola `[ALERT]` satırı basılır ve — yapılandırılmışsa — bildirim gönderilir / IP engellenir.

## Durum

- **Sniffer** ([include/sniffer.hpp](include/sniffer.hpp)/[src/sniffer.cpp](src/sniffer.cpp)): libpcap ile bir ağ arayüzünü promiscuous modda açar, paketleri sonsuz döngüde yakalar, `SIGINT` (Ctrl+C) ile güvenli şekilde durur.
- **Parser** ([include/parser.hpp](include/parser.hpp)/[src/parser.cpp](src/parser.cpp)): Ethernet / loopback / Linux "cooked capture" link katmanlarını, IPv4 başlığını ve TCP/UDP/ICMP başlıklarını ayrıştırır.
- **Rules** ([include/rules.hpp](include/rules.hpp)/[src/rules.cpp](src/rules.cpp)):
  - `PortScanDetector` — aynı kaynak IP kısa bir zaman penceresinde (varsayılan 5 sn) çok sayıda farklı porta (varsayılan 15+) eriştiğinde uyarı üretir.
  - `SynFloodDetector` — aynı kaynak IP kısa bir zaman penceresinde (varsayılan 5 sn) çok sayıda "saf" SYN paketi (el sıkışmayı tamamlamadan, varsayılan 100+) gönderdiğinde uyarı üretir.
- **Threat Intelligence** ([include/threat_intel.hpp](include/threat_intel.hpp)/[src/threat_intel.cpp](src/threat_intel.cpp)): `ABUSEIPDB_API_KEY` ayarlıysa her IP'yi arka plan thread'inde AbuseIPDB'ye sorar, sonuçları cache'ler (varsayılan 1 saat).
- **Notifier** ([include/notifier.hpp](include/notifier.hpp)/[src/notifier.cpp](src/notifier.cpp)): Discord webhook ve/veya Telegram bot üzerinden alert'leri gerçek zamanlı gönderir; rate-limit korumalı.
- **Firewall / IPS** ([include/firewall.hpp](include/firewall.hpp)/[src/firewall.cpp](src/firewall.cpp)): `FALCON_IPS_ENABLED=1` ile aktifleşir; `iptables`/`ufw` üzerinden saldırgan IP'leri otomatik engeller (strike eşiği veya yüksek AbuseIPDB skoru ile). Private IP'ler ve whitelist korunur.
- **Testler** ([tests/](tests/)): `test_parser` ve `test_rules` — harici framework olmadan, `ctest` ile çalışır.
- **CI** ([.github/workflows/ci.yml](.github/workflows/ci.yml)): her push/PR'da Ubuntu üzerinde derleme + test.
- **AWS altyapısı** ([infrastructure/terraform/](infrastructure/terraform/)): FalconIDS'i tek komutla bir EC2 sunucusuna kuran Terraform tanımı (opsiyonel).

Henüz eklenmedi: ARP spoofing tespiti, kalıcı dosya/JSON loglama, yapılandırma dosyası (şu an sadece env değişkenleri).

## Gereksinimler

- Linux (ham paket yakalama için gerekli)
- CMake ≥ 3.15
- C++17 destekleyen bir derleyici (GCC/Clang)
- libpcap geliştirme başlıkları (`libpcap-dev`)
- libcurl geliştirme başlıkları (`libcurl4-openssl-dev`) — Threat Intelligence ve Notifier modülleri için

## Kurulum

Bağımlılıkları tek seferde kurmak için:

```bash
sudo ./scripts/setup_linux.sh
```

## Derleme

```bash
cmake -S . -B build
cmake --build build
```

## Testleri çalıştırma

```bash
ctest --test-dir build --output-on-failure
```

## Kullanım

Ham soket erişimi gerektirdiği için `root` yetkisiyle (ya da `cap_net_raw`/`cap_net_admin` capability'leriyle) çalıştırılmalıdır:

```bash
sudo ./build/netfalcon <arayuz-adi>
# ornek:
sudo ./build/netfalcon eth0
```

Threat Intelligence, bildirimler ve otomatik engelleme tamamen opsiyoneldir — `.env.example` dosyasını kopyalayıp doldurun:

```bash
cp .env.example .env
source .env
sudo -E ./build/netfalcon eth0   # -E: env degiskenlerini sudo'ya tasi
```

Dinlerken port taraması tespit edilirse konsola şu formatta bir uyarı basılır:

```
[ALERT] Olasi port taramasi: 127.0.0.1 son 5 saniyede 18 farkli porta eristi (esik: 15)
[ALERT] Olasi SYN flood: 198.51.100.23 son 5 saniyede 120 SYN paketi gonderdi (esik: 100)
```

Durdurmak için `Ctrl+C`.

## Proje Yapısı

```
FalconIDS/
├── CMakeLists.txt              # Derleme kuralları
├── LICENSE                     # MIT
├── .github/workflows/ci.yml    # CI: derleme + testler
├── include/                     # Başlık dosyaları
│   ├── sniffer.hpp              # Ağ kartını dinleyen çekirdek sınıf
│   ├── parser.hpp                # Paket ayrıştırma
│   ├── rules.hpp                 # Tespit kuralları (port taraması, SYN flood)
│   ├── threat_intel.hpp          # AbuseIPDB entegrasyonu
│   ├── notifier.hpp               # Discord/Telegram bildirimleri
│   └── firewall.hpp                # iptables/ufw ile otomatik engelleme
├── src/                            # Kaynak dosyaları
│   ├── main.cpp                    # Giriş noktası, CLI argümanları, env yapılandırması
│   ├── sniffer.cpp
│   ├── parser.cpp
│   ├── rules.cpp
│   ├── threat_intel.cpp
│   ├── notifier.cpp
│   └── firewall.cpp
├── tests/                          # Birim testleri (ctest)
│   ├── test_parser.cpp
│   ├── test_rules.cpp
│   └── packet_builder.hpp          # Testler icin sahte paket olusturucu
├── third_party/nlohmann/json.hpp   # Vendored JSON kütüphanesi
├── infrastructure/terraform/       # AWS'de tek komutla dağıtım (opsiyonel)
├── scripts/
│   └── setup_linux.sh              # Bağımlılık kurulum scripti
├── .env.example                    # Opsiyonel env değişkenleri şablonu
└── build/                          # Derleme çıktıları (Git'e eklenmez)
```

## Yol Haritası

- [x] `tests/` altında parser ve rules için birim testleri
- [x] SYN flood tespiti
- [x] CI (GitHub Actions)
- [x] LICENSE
- [ ] ARP spoofing tespiti
- [ ] Yapılandırma dosyası (env değişkenleri yerine/yanında YAML/TOML)
- [ ] Kalıcı loglama (dosya/JSON çıktısı)
- [ ] BPF filtre desteği (`-f "tcp port 22"` gibi CLI filtreleri)
