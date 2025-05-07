#ifndef WIFISORT_H
#define WIFISORT_H

#include "wifitypes.h"

int is_upc07ubee_mac(const char *mac);
int is_upc07_ssid(const char *ssid);
KeygenType detect_keygen(const Network *net);

#endif