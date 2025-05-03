#include <stdio.h>
#include "wifitypes.h"
#include "scan.h"
#include "wifisort.h"
#include "passgen.h"

int main() {
    printf("Vítejte v keygenu\n");

    Network networks[MAX_NETWORKS];
    Network filtered[MAX_NETWORKS];
    int count, fcount = 0;

    printf("Skenuji okolní WiFi sítě...\n");
    count = scan_wifi(networks);

    if (count == 0) {
        printf("Žádná WiFi síť nenalezena.\n");
        printf("Ukončuji keygen\n");
        return 0;
    }

    // Filtrování
    for (int i = 0; i < count; ++i) {
        KeygenType tkg = detect_keygen(&networks[i]);
        if (tkg != NONE) {
            filtered[fcount++] = networks[i];
        }
    }

    if (fcount == 0) {
        printf("Žádná kompatibilní síť nenalezena.\n");
        printf("Ukončuji keygen\n");
        return 0;
    }

    for (int i = 0; i < fcount; ++i) {
        char upcpass[32];
        printf("\nSSID: %s\nMAC: %s\nSíla signálu: %d dBm\nMožná hesla:\n", 
            filtered[i].ssid, filtered[i].mac, filtered[i].signal);
        KeygenType tkg = detect_keygen(&filtered[i]);
        if (tkg == UPC07UBEE) {
            upc07ubee_generate_pass(filtered[i].mac, upcpass);
            printf("  [Upc07UbeeKeygen] %s\n", upcpass);
        }
        if (tkg == UPC07) {
            upc07keygen_demo(filtered[i].ssid, upcpass);
            printf("  [Upc07Keygen] %s (demo, není skutečné heslo)\n", upcpass);
        }
    }    
    printf("Ukončuji keygen\n");
    return 0;
}