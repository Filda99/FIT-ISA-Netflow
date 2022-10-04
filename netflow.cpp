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
#include <map>
#include <tuple>

using namespace std;
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

struct flow_record {
    uint32_t srcIP;         // Source IP address 
    uint32_t dstIP;         // Destination IP address 
    uint32_t nextHop;       // IP address of next hop router 
    uint16_t scrIf = 0;     // SNMP index of input interface 
    uint16_t dstIf = 0;     // SNMP index of output interface 
    uint32_t dPkts = 0;     // Packets in the flow 
    uint32_t dOctets = 0;   // Total number of Layer 3 bytes in the packets of the flow 
    uint32_t first = 0;     // SysUptime at start of flow 
    uint32_t last = 0;      // SysUptime at the time the last packet of the flow was received 
    uint16_t srcPort = 0;   // TCP/UDP source port number or equivalent 
    uint16_t dstPort = 0;   // TCP/UDP destination port number or equivalent 
    uint8_t  pad1 = 0;      // Unused (zero) bytes 
    uint8_t  flgs = 0;      // Cumulative OR of TCP flags 
    uint8_t  prot = 0;      // IP protocol type
    uint8_t  tos = 0;       // IP type of service (ToS) 
    uint16_t srcAs = 0;     // Autonomous system number of the source, either origin or peer
    uint16_t dstAs = 0;     // Autonomous system number of the destination, either origin or peer 
    uint8_t  srcMask = 32;  // Source address prefix mask bits 
    uint8_t  dstMask = 32;  // Destination address prefix mask bits 
    uint16_t pad2 = 0;      // Unused (zero) bytes 
};

/************************************
 * STATIC VARIABLES
 ************************************/

/************************************
 * GLOBAL VARIABLES
 ************************************/
string pcapFile_name = "-";
string netflow_collector = "127.0.0.1:2055";
int active_timer = 60;
int inactive_timer = 10;
int flowcache_size = 1024;
map< tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>, flow_record >flow_map;

/************************************
 * STATIC FUNCTION PROTOTYPES
 ************************************/
void parse_arguments(int argc, char **argv);
void icmp_v4(flow_record flow);
void udp_v4(flow_record flow, const u_char *transportProtocolHdr);
void tcp_v4(flow_record flow, const u_char *transportProtocolHdr);
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
    int c;
    while((c = getopt(argc, argv, "f:c:a:i:m:")) != -1){
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
void icmp_v4(flow_record flow)
{
    // srcIP, dstIP, srcPort, dstPort, protocol
    tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> keys = make_tuple(flow.srcIP, flow.dstIP, 0u, 0u, flow.prot);
    flow_map[keys] = flow;
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
void udp_v4(flow_record flow, const u_char *transportProtocolHdr)
{
    struct udphdr *udpHdr = (struct udphdr *) transportProtocolHdr; // udp struktura
    flow.srcPort = ntohs(udpHdr->uh_sport);
    flow.dstPort = ntohs(udpHdr->uh_dport);

    // srcIP, dstIP, srcPort, dstPort, protocol
    tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> keys = make_tuple(flow.srcIP, flow.dstIP, flow.srcPort, flow.dstPort, flow.prot);
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
void tcp_v4(flow_record flow, const u_char *transportProtocolHdr)
{
    struct tcphdr* tcpHdr = (struct tcphdr*)transportProtocolHdr; // udp struktura
    flow.srcPort = ntohs(tcpHdr->th_sport);
    flow.dstPort = ntohs(tcpHdr->th_dport);
    flow.flgs = tcpHdr->th_flags; 

    // srcIP, dstIP, srcPort, dstPort, protocol
    tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> keys = make_tuple(flow.srcIP, flow.dstIP, flow.srcPort, flow.dstPort, flow.prot);
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
    cout << "TIme: " << header->ts.tv_sec << "\n";
    flow_record flow;

    struct ether_header *ipvNum = (struct ether_header*)packet;
    u_short type = ntohs(ipvNum->ether_type);

    // Posunuti se v paketu o ethernetovou hlavicku
    const u_char *packetIP = packet + ETH_HDR;
    struct ip *ipHeader = (struct ip*)packetIP;


    if(type == 0x0800){ //ipv4
        flow.prot = ipHeader->ip_p;
        flow.tos = ipHeader->ip_tos;
        flow.srcIP = ipHeader->ip_src.s_addr;
        flow.dstIP = ipHeader->ip_dst.s_addr;
        flow.dOctets = ipHeader->ip_len - ETH_HDR;

        switch (ipHeader->ip_p) {
            // ICMP
            case 1:
                icmp_v4(flow);
                break;

            // TCP + UDP
            case 6:
            case 17:{ // V zavorkach kvuli deklarovani promenne
                // Promenliva delka hlavicky
                unsigned int ipLen = ipHeader->ip_hl * 4;
                const u_char *transportProtocolHdr = packet + ETH_HDR + ipLen;

                if(ipHeader->ip_p == 17)
                    udp_v4(flow, transportProtocolHdr);
                else
                    tcp_v4(flow, transportProtocolHdr);
                break;
            }

            default:
                break;
        }
    }
}

int pcap_set_filter(pcap_t *handle)
{
    string filterStr = "(tcp or udp or icmp)";
    struct bpf_program fp;
    bpf_u_int32 net;

    if (pcap_compile(handle, &fp, filterStr.c_str(), 0, net) == -1) {
        fprintf(stderr, "[ERR]: Parsování filtru se neydařilo %s: %s\n", filterStr.c_str(), pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "[ERR]: Filtr se nepodařilo uložit do pcap %s: %s\n", filterStr.c_str(), pcap_geterr(handle));
        return(2);
    }
    return 1;
}

int main (int argc, char **argv)
{
    if (argc == 1){
        exit(1);
    }
    parse_arguments(argc, argv);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Otevreni zarizeni pro sledovani paketu
    handle = pcap_open_offline(pcapFile_name.c_str(), errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERR]: Nepodařilo se mi otevřít soubor %s, %s\n",pcapFile_name.c_str(), errbuf);
        return(2);
    }

    if (pcap_set_filter(handle) != 1){
        pcap_close(handle);
        return(2);
    }
    
    pcap_loop(handle, 0, process_packet, NULL);

    pcap_close(handle);

    return(0);
}


/************************************
 * GLOBAL FUNCTIONS
 ************************************/