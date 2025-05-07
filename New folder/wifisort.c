#include "wifisort.h"
#include <string.h>
#include <ctype.h>

int is_upc07ubee_mac(const char *mac) {
    return strncasecmp(mac, "64:7C:34", 8) == 0;
}
int is_upc07_ssid(const char *ssid) {
    if (strncmp(ssid, "UPC", 3) != 0)
        return 0;
    for (int i = 3; i < 10; i++) {
        if (!isdigit((unsigned char)ssid[i]))
            return 0;
    }
    return ssid[10] == '\0';
}
KeygenType detect_keygen(const Network *net) {
    if (is_upc07ubee_mac(net->mac))
        return UPC07UBEE;
    if (is_upc07_ssid(net->ssid))
        return UPC07;
    return NONE;
}