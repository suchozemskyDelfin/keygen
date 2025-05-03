#include "scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int scan_wifi(Network networks[MAX_NETWORKS]) {
    FILE *fp;
    char line[512];
    Network net;
    int found = 0;
    int in_cell = 0;

    fp = popen("iwlist wlan1 scan 2>/dev/null", "r");
    if (!fp) {
        perror("popen");
        return 0;
    }

    memset(&net, 0, sizeof(Network));
    net.signal = -999; // pro jistotu, hodnota která znamená "nezjištěno"

    while (fgets(line, sizeof(line), fp)) {
        char *ptr;
        // Začátek nového záznamu
        if (strstr(line, "Cell ")) {
            if (in_cell && strlen(net.ssid) > 0 && strlen(net.mac) > 0) {
                if (found < MAX_NETWORKS)
                    networks[found++] = net;
            }
            memset(&net, 0, sizeof(Network));
            net.signal = -999; // opět nastavit default
            in_cell = 1;
            ptr = strstr(line, "Address: ");
            if (ptr) {
                strncpy(net.mac, ptr + 9, 17);
                net.mac[17] = 0;
            }
        }
        // ESSID:
        ptr = strstr(line, "ESSID:\"");
        if (ptr) {
            sscanf(ptr + 7, "%63[^\"]", net.ssid);
        }
        // Signal level:
        ptr = strstr(line, "Signal level=");
        if (ptr) {
            int level;
            // Může to být: "Signal level=-43 dBm" nebo "Signal level=43/70"
            if (sscanf(ptr + 13, "%d", &level) == 1) {
                net.signal = level;
            }
        }
    }
    if (in_cell && strlen(net.ssid) > 0 && strlen(net.mac) > 0) {
        if (found < MAX_NETWORKS)
            networks[found++] = net;
    }
    pclose(fp);
    return found;
}