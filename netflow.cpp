/*********************************************************************************************************************
 * Předmět:     ISA - Síťové aplikace a správa sítí
 * Projekt:     Generování NetFlow dat ze zachycené síťové komunikace
 * Datum:       10/2022
 * @file:       netflow.c    
 * @author:     Filip Jahn
 * Login:       xjahnf00
 *
 * *******************************************************************************************************************
 * @brief:
 * V rámci projektu implementujte NetFlow exportér, který ze zachycených síťových dat ve formátu pcap 
 * vytvoří záznamy NetFlow, které odešle na kolektor.
 * *******************************************************************************************************************
 * Spuštění:
 * ./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]
 *      - f <file> - jméno analyzovaného souboru nebo STDIN
 *      - c <neflow_collector:port> - IP adresa, nebo hostname NetFlow kolektoru. Volitelně i UDP port
 *      - a <active_timer> - interval v sekundách, po kterém se exportují aktivní záznamy na kolektor
 *      - i <seconds> - interval v sekundách, po jehož vypršení se exportují neaktivní záznamy na kolektor
 *      - m <count> - velikost flow-cache. Při dosažení max. velikosti dojde k exportu nejstaršího záznamu v cachi na kolektor
 * 
 * *******************************************************************************************************************
 */


/************************************
 * INCLUDES
 ************************************/
#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <arpa/inet.h>          //inet_ntoa(), inet_ntop()
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>    //icmp hlavicka
#include <netinet/udp.h>        //udp hlavicka
#include <netinet/tcp.h>        //tcp hlavicka
#include <netinet/if_ether.h>   //ethernet hlavicka
#include <netinet/ip.h>         //ip hlavicka
//#include <math.h>               //ceil()

/************************************
 * EXTERN VARIABLES
 ************************************/

/************************************
 * PRIVATE MACROS AND DEFINES
 ************************************/
#define ETH_HDR  14

/************************************
 * PRIVATE TYPEDEFS
 ************************************/

/************************************
 * STATIC VARIABLES
 ************************************/

/************************************
 * GLOBAL VARIABLES
 ************************************/
std::string pcapFile_name = "-";
std::string netflow_collector = "127.0.0.1:2055";
int active_timer = 60;
int inactive_timer = 10;
int flowcache_size = 1024;

/************************************
 * STATIC FUNCTION PROTOTYPES
 ************************************/
void parse_arguments(int argc, char **argv);
void icmp_v4(std::string srcIP, std::string dstIP);
void udp_v4(std::string srcIP, std::string dstIP, const u_char *transportProtocolHdr, bpf_u_int32 lengthOfPacket,
              std::string currentTime);
void tcp_v4(std::string srcIP, std::string dstIP, const u_char *transportProtocolHdr, bpf_u_int32 lengthOfPacket,
              std::string currentTime);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/************************************
 * STATIC FUNCTIONS
 ************************************/
/**
 * Parsovani argumentu.
 * Argumenty mohou byt zadany nasledovne:
 * [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} {-n num}
 * @param argc Pocet argumentu
 * @param argv Pole zadanych argumentu
 */
void parse_arguments(int argc, char **argv)
{
    bool checkInterface = false;

    int c;
    while((c = getopt(argc, argv, "f:c:a:i:m:")) != -1){
        printf("%c\n", c);
        switch (c)
        {
            case 'f':
                pcapFile_name = optarg;
                break;

            case 'c':
                netflow_collector = optarg;
                break;

            case 'a':
                if ((active_timer = atoi(optarg)) == 0){
                    fprintf(stderr, "[ERR]: Parametru -a lze priradit pouze int.\n");
                    exit(3);
                }
                break;

            case 'i':
                if ((inactive_timer = atoi(optarg)) == 0){
                    fprintf(stderr, "[ERR]: Parametru -i lze priradit pouze int.\n");
                    exit(3);
                }
                break;

            case 'm':
                if ((flowcache_size = atoi(optarg)) == 0){
                    fprintf(stderr, "[ERR]: Parametru -m lze priradit pouze int.\n");
                    exit(3);
                }
                break;

            default:
                // TODO: cekat a cist data ze STDIN
                break;
        }
    }
}

/**
 * Zpracovani a vypsani protokolu icmp pro ipv4.
 * Ze zacatku pretypovani paketu na ip strukturu, ziskani ip adres, vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka paketu
 * @param currentTime Cas obdrzeni paketu
 */
void icmp_v4(std::string srcIP, std::string dstIP)
{
    printf("\n(ICMPv4)");
}

/**
 * Zpracovani a vypsani protokolu udp pro ipv4.
 * Ze zacatku pretypovani paketu na ip strukturu, pote ziskani ip adres,
 * posunuti se v paketu o delku hlavicky, pretypovani na upd strukturu,
 * zjisteni portu a nasledne vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka paketu
 * @param currentTime Cas obdrzeni paketu
 * @param ipLen Delka hlavicky, o kterou se mame posunout pro ziskani portu
 */
void udp_v4(std::string srcIP, std::string dstIP, const u_char *transportProtocolHdr, bpf_u_int32 lengthOfPacket,
              std::string currentTime)
{
    printf("\n(UDPv4)");
    
    struct udphdr *udpHdr = (struct udphdr *) transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(udpHdr->uh_sport);
    uint16_t dstPort = ntohs(udpHdr->uh_dport);
}

/**
 * Zpracovani a vypsani protokolu tcp pro ipv4.
 * Ze zacatku pretypovani paketu na ip strukturu, pote ziskani ip adres,
 * posunuti se v paketu o delku hlavicky, pretypovani na tcp strukturu,
 * zjisteni portu a nasledne vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka paketu
 * @param currentTime Cas obdrzeni paketu
 * @param ipLen Delka hlavicky, o kterou se mame posunout pro ziskani portu
 */
void tcp_v4(std::string srcIP, std::string dstIP, const u_char *transportProtocolHdr, bpf_u_int32 lengthOfPacket,
              std::string currentTime)
{
    printf("\n(TCPv4)");

    struct tcphdr* tcpHdr = (struct tcphdr*)transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(tcpHdr->th_sport);
    uint16_t dstPort = ntohs(tcpHdr->th_dport);
}

/**
 * Hlavni funkce, vola se vzdy pri prijeti paketu.
 * Zpracovani ethernetove hlavicky, zjisteni, ktery protokol se vyuziva a
 * nasledne volani funkce se zpracovanim daneho protokolu nad timto packetem.
 * @param args Argumenty, ktere nevyuzivam. MUSI zde byt. Pcap si tento argument zada
 * @param header Vyuziti pro zjisteni delky celeho paketu
 * @param packet Odchyceny packet
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
    struct ether_header *ipvNum = (struct ether_header*)packet;
    u_short type = ntohs(ipvNum->ether_type);
    // Aktualni cas prijeti paketu
    // TODO: add time from packet header
    std::string currentTime = "";

    // Posunuti se v paketu o ethernetovou hlavicku
    const u_char *packetIP = packet + ETH_HDR;

    std::string srcIp = "";
    std::string dstIP = "";

    struct ip* ipHdr = (struct ip*)packetIP;
    srcIp.append(inet_ntoa(ipHdr->ip_src));
    dstIP.append(inet_ntoa(ipHdr->ip_dst));
    
    if(type == 0x0800){ //ipv4
        struct iphdr *ipHeader = (struct iphdr*)packetIP;

        switch (ipHeader->protocol) {
            // ICMP
            case 1:
                icmp_v4(srcIp, dstIP);
                break;

            // TCP + UDP
            case 6:
            case 17:{ // V zavorkach kvuli deklarovani promenne
                // Promenliva delka hlavicky
                unsigned int ipLen = ipHeader->ihl * 4;
                const u_char *transportProtocolHdr = packet + ETH_HDR + ipLen;

                if(ipHeader->protocol == 17)
                    udp_v4(srcIp, dstIP, transportProtocolHdr, header->len, currentTime);
                else
                    tcp_v4(srcIp, dstIP, transportProtocolHdr, header->len, currentTime);
                break;
            }

            default:
                break;
        }
    }
}

int main (int argc, char **argv)
{
    if (argc == 1){
        exit(1);
    }
    parse_arguments(argc, argv);

    pcap_t *handle;
    struct pcap_pkthdr header;
    const uint8_t *packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string filterStr = "(tcp or udp or icmp)";
    struct bpf_program fp;
    bpf_u_int32 net;

    // Otevreni zarizeni pro sledovani paketu
    printf("File: %s", pcapFile_name.c_str());
    handle = pcap_open_offline(pcapFile_name.c_str(), errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERR]: Nepodařilo se mi otevřít soubor %s, %s\n",pcapFile_name.c_str(), errbuf);
        return(2);
    }
    if (pcap_compile(handle, &fp, filterStr.c_str(), 0, net) == -1) {
        fprintf(stderr, "[ERR]: Parsování filtru se neydařilo %s: %s\n", filterStr.c_str(), pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[ERR]: Filtr se nepodařilo uložit do pcap %s: %s\n", filterStr.c_str(), pcap_geterr(handle));
        return(2);
    }
    // while(packet = pcap_next(handle, &header))
    // {
    //     printf("Got packet!");
    // }

    pcap_loop(handle, 0, process_packet, NULL);
    

    pcap_close(handle);

    return(0);
}


/************************************
 * GLOBAL FUNCTIONS
 ************************************/