#ifndef PASSGEN_H
#define PASSGEN_H

#include "wifitypes.h"

void upc07ubee_generate_pass(const char *mac_str, char *pass);
void upc07keygen(const char *ssid, char *pass);

#endif