cmake_minimum_required(VERSION 3.15)
project(NetFalcon VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# --- libpcap ---------------------------------------------------------------
# CMake'in resmi bir FindPCAP modulu yok; basliklari ve kutuphaneyi elle ariyoruz.
# Linux: 'sudo apt install libpcap-dev' (bkz. scripts/setup_linux.sh)
# Windows: Npcap SDK kurulup PCAP_ROOT ile CMake'e gosterilmeli.
find_path(PCAP_INCLUDE_DIR NAMES pcap.h HINTS "$ENV{PCAP_ROOT}/Include")
find_library(PCAP_LIBRARY NAMES pcap wpcap HINTS "$ENV{PCAP_ROOT}/Lib/x64" "$ENV{PCAP_ROOT}/Lib")

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR
        "libpcap/Npcap bulunamadi.\n"
        "  Linux : sudo apt install libpcap-dev\n"
        "  Windows: Npcap SDK indirip PCAP_ROOT ortam degiskenini kurulum yoluna ayarlayin.")
endif()

add_library(netfalcon_core
    src/sniffer.cpp
)
target_include_directories(netfalcon_core PUBLIC include ${PCAP_INCLUDE_DIR})
target_link_libraries(netfalcon_core PUBLIC ${PCAP_LIBRARY})

if(WIN32)
    target_link_libraries(netfalcon_core PUBLIC ws2_32)
endif()

if(MSVC)
    target_compile_options(netfalcon_core PRIVATE /W4)
else()
    target_compile_options(netfalcon_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(netfalcon src/main.cpp)
target_link_libraries(netfalcon PRIVATE netfalcon_core)
