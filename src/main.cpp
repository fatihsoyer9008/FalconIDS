#include "sniffer.hpp"

#include <csignal>
#include <iostream>

namespace {

netfalcon::Sniffer* g_activeSniffer = nullptr;

void handleInterrupt(int) {
    if (g_activeSniffer != nullptr) {
        g_activeSniffer->stop();
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Kullanim: " << argv[0] << " <ag-arayuzu>\n";
        std::cerr << "Ornek:    " << argv[0] << " eth0\n";
        return 1;
    }

    netfalcon::Sniffer sniffer(argv[1]);
    g_activeSniffer = &sniffer;
    std::signal(SIGINT, handleInterrupt);

    if (!sniffer.open()) {
        return 1;
    }

    sniffer.run();
    return 0;
}
