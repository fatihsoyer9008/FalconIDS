#!/usr/bin/env bash
# Ubuntu/Debian tabanli sistemlerde NetFalcon derlemesi icin gereken
# bagimliliklari (libpcap basliklari, cmake, derleyici arac zinciri) kurar.
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Bu script sudo ile calistirilmali: sudo ./scripts/setup_linux.sh" >&2
    exec sudo -- "$0" "$@"
fi

apt-get update
apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    libcurl4-openssl-dev

echo "Bagimliliklar kuruldu. Derlemek icin:"
echo "  cmake -S . -B build && cmake --build build"
