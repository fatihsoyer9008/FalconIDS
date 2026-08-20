# FalconIDS

C++17 ve libpcap ile geliştirilen, performans odaklı bir ağ trafiği analiz (IDS/Sniffer) aracı. Ağ arayüzünü promiscuous modda dinler, geçen paketleri ayrıştırır ve basit anomali kurallarıyla (ör. port taraması) şüpheli trafiği tespit eder.

## Nasıl çalışır

```
  Ağ Arayüzü (promiscuous)
          │  libpcap
          ▼
   ┌─────────────┐      ┌─────────────┐      ┌───────────────────┐
   │   Sniffer   │ ───▶ │   Parser    │ ───▶ │  Rules / Detector  │ ───▶ [ALERT]
   │ sniffer.hpp │      │ parser.hpp  │      │    rules.hpp       │
   └─────────────┘      └─────────────┘      └───────────────────┘
   ham paketi yakalar    Ethernet/IPv4/       örn. PortScanDetector:
   (sonsuz döngü)        TCP/UDP/ICMP         zaman penceresinde
                         başlıklarını         çok sayıda farklı porta
                         ayrıştırır           erişimi yakalar
```

Her paket bu üç aşamadan sırayla geçer: **yakala → ayrıştır → kurala karşı değerlendir**. Bir kural tetiklenirse konsola insan-okunabilir bir `[ALERT]` satırı basılır.

## Durum

Proje erken (iskelet) aşamada. Şu an çalışan kısımlar:

- **Sniffer**: libpcap ile bir ağ arayüzünü promiscuous modda açar, paketleri sonsuz döngüde yakalar, `SIGINT` (Ctrl+C) ile güvenli şekilde durur.
- **Parser**: Ethernet / loopback / Linux "cooked capture" link katmanlarını, IPv4 başlığını ve TCP/UDP/ICMP başlıklarını ayrıştırır.
- **Rules**: `PortScanDetector` — aynı kaynak IP kısa bir zaman penceresinde (varsayılan 5 sn) çok sayıda farklı porta (varsayılan 15+) eriştiğinde uyarı üretir.

Henüz eklenmedi: birim testleri (`tests/`), ek tespit kuralları, kalıcı loglama/raporlama.

## Gereksinimler

- Linux (ham paket yakalama için gerekli)
- CMake ≥ 3.15
- C++17 destekleyen bir derleyici (GCC/Clang)
- libpcap geliştirme başlıkları (`libpcap-dev`)

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

## Kullanım

Ham soket erişimi gerektirdiği için `root` yetkisiyle (ya da `cap_net_raw`/`cap_net_admin` capability'leriyle) çalıştırılmalıdır:

```bash
sudo ./build/netfalcon <arayuz-adi>
# ornek:
sudo ./build/netfalcon eth0
```

Dinlerken port taraması tespit edilirse konsola şu formatta bir uyarı basılır:

```
[ALERT] Olasi port taramasi: 127.0.0.1 son 5 saniyede 18 farkli porta eristi (esik: 15)
```

Durdurmak için `Ctrl+C`.

## Proje Yapısı

```
FalconIDS/
├── CMakeLists.txt         # Derleme kuralları
├── include/                # Başlık dosyaları
│   ├── sniffer.hpp         # Ağ kartını dinleyen çekirdek sınıf
│   ├── parser.hpp          # Paket ayrıştırma
│   └── rules.hpp           # Tespit kuralları (ör. port taraması)
├── src/                     # Kaynak dosyaları
│   ├── main.cpp             # Giriş noktası, CLI argümanları
│   ├── sniffer.cpp
│   ├── parser.cpp
│   └── rules.cpp
├── scripts/
│   └── setup_linux.sh       # Bağımlılık kurulum scripti
└── build/                    # Derleme çıktıları (Git'e eklenmez)
```

## Yol Haritası

- [ ] `tests/` altında parser ve rules için birim testleri
- [ ] Ek tespit kuralları (ör. SYN flood, ARP spoofing)
- [ ] Yapılandırılabilir eşikler (config dosyası / CLI parametreleri)
- [ ] Kalıcı loglama (dosya/JSON çıktısı)
