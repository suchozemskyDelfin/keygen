#ifndef WIFITYPES_H
#define WIFITYPES_H

#define MAX_NETWORKS 100
#define MAX_LEN 64

typedef struct {
    char ssid[MAX_LEN];
    char mac[MAX_LEN];
    int signal; // Síla signálu v dBm (záporné číslo)
} Network;

typedef enum { NONE, UPC07, UPC07UBEE } KeygenType;

#endif