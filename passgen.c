#include "passgen.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>

static void macstr_to_bytes(const char *mac_str, unsigned char *bytes) {
    int i = 0, j = 0;
    while(i < 12 && j < 6){
        int hi = toupper(mac_str[i]) < 'A' ? mac_str[i] - '0' : toupper(mac_str[i]) - 'A' + 10;
        int lo = toupper(mac_str[i+1]) < 'A' ? mac_str[i+1] - '0' : toupper(mac_str[i+1]) - 'A' + 10;
        bytes[j++] = hi * 16 + lo;
        i += 2;
        if (mac_str[i] == ':' || mac_str[i] == '-') i++;
    }
}

void upc07ubee_generate_pass(const char *mac_str, char *pass) {
    unsigned char mac[6];
    macstr_to_bytes(mac_str, mac);
    MD5_CTX ctx;
    unsigned char buff1[100] = {0};
    unsigned char buff2[100] = {0};
    unsigned char buff3[100] = {0};
    unsigned char hash_buff[100] = {0};
    sprintf((char*)buff1, "%02X%02X%02X%02X%02X%02X555043444541554C5450415353504852415345",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    MD5_Init(&ctx);
    MD5_Update(&ctx, buff1, strlen((char*)buff1)+1);
    MD5_Final(buff2, &ctx);
    sprintf((char*)buff3, "%.02X%.02X%.02X%.02X%.02X%.02X", buff2[0]&0xf, buff2[1]&0xf, buff2[2]&0xf, buff2[3]&0xf, buff2[4]&0xf, buff2[5]&0xf);
    MD5_Init(&ctx);
    MD5_Update(&ctx, buff3, strlen((char*)buff3)+1);
    MD5_Final(hash_buff, &ctx);
    for (int i = 0; i < 8; ++i)
        pass[i] = 0x41u + ((hash_buff[i] + hash_buff[i+8]) % 0x1Au);
    pass[8] = '\0';
}

// DEMO (nikoli skutečný algoritmus)
void upc07keygen_demo(const char *ssid, char *pass) {
    snprintf(pass, 9, "UPC-HESL");
}