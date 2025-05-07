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

     printf("Nalezeno %d WiFi sítí:\n", count);
     for (int i = 0; i < count; ++i) {
          printf("  SSID: %s\n  MAC: %s\n  Síla signálu: %d dBm\n\n",
                 networks[i].ssid,
                 networks[i].mac,
                 networks[i].signal);
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
    printf("\nSSID: %s\nMAC: %s\nSíla signálu: %d dBm\nMožná hesla:\n", 
        filtered[i].ssid, filtered[i].mac, filtered[i].signal);
    KeygenType tkg = detect_keygen(&filtered[i]);
    if (tkg == UPC07UBEE) {
        char upcpass[32];
        upc07ubee_generate_pass(filtered[i].mac, upcpass);
        printf("  [Upc07UbeeKeygen] %s\n", upcpass);
    }
    if (tkg == UPC07) {
        // Najdi všechna možná hesla!
        char passes[8][9];   // Každé heslo má 8 znaků + '\0', maximálně 8 variant (reálně bývají 1-4)
        int n = upc07keygen_multi(filtered[i].ssid, passes, 8);
        if (n == 0) {
            printf("  [Upc07Keygen] Není nalezeno žádné heslo!\n");
        } else {
            for (int j = 0; j < n; ++j) {
                printf("  [Upc07Keygen %d] %s\n", j+1, passes[j]);
           }
        }
     }
  }
    printf("Ukončuji keygen\n");
    return 0;
}