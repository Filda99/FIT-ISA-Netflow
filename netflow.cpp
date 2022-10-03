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
#include <net/if_arp.h>         //arp hlavicka
#include <netinet/ip.h>         //ip hlavicka
#include <netinet/ip6.h>        //ipv6 hlavicka
//#include <math.h>               //ceil()

/************************************
 * EXTERN VARIABLES
 ************************************/

/************************************
 * PRIVATE MACROS AND DEFINES
 ************************************/
#define ETH_HDR  14
//#define IPV4_PROT   0
//#define IPV6_PROT   1
#define IPV6_HDR    40

/************************************
 * PRIVATE TYPEDEFS
 ************************************/

/************************************
 * STATIC VARIABLES
 ************************************/

/************************************
 * GLOBAL VARIABLES
 ************************************/
// Boolean hodnoty, ktere protokoly se maji zobrazovat
bool tcp = false;
bool udp = false;
bool arp = false;
bool icmp = false;

// Rozhranni, na kterem se posloucha
char* device;

// Port
char* port = (char*)"0";

// Pocet paketu, kolik se jich ma zobrazit
// Defaultne 1
int numOfPackets = 1;

FILE *pcapFile;
std::string pcapFile_name = "";
std::string netflow_collector = "127.0.0.1:2055";
int active_timer = 60;
int inactive_timer = 10;
int flowcache_size = 1024;

/************************************
 * STATIC FUNCTION PROTOTYPES
 ************************************/
void parse_arguments(int argc, char **argv);
std::string fill_filter_str(std::string str);
std::string time_rfc3339();
void icmp_v4(const u_char *packetWoEther,  const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime);
void icmp_v6(const u_char *packetWoEther,  const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime);
void udp_v4(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket,
              std::string currentTime, unsigned int ipLen);
void udp_v6(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime);
void tcp_v4(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket,
              std::string currentTime, unsigned int ipLen);
void tcp_v6(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime);
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
 * Naplni pole filterStr retezcem.
 * Ve funkci pcap_compile(), kam retezec posilame, probehne zpracovani tohoto retezce
 * a tim se nam vrati spravna struktura.
 * @param str Retezec, ktery se ma naplnit
 */
std::string fill_filter_str(std::string str)
{
    bool addNextProtocol = false;
    if (strcmp(port, "0") != 0){
        str.append("port ");
        str.append(port);
        str.append(" and ");
    }
    str.append(" (");
    if(tcp){
        str.append("tcp");
        addNextProtocol = true;
    }
    if(udp){
        if (addNextProtocol)
            str.append(" or ");
        str.append("udp");
        addNextProtocol = true;
    }
    if(arp){
        if (addNextProtocol)
            str.append(" or ");
        str.append("arp");
        addNextProtocol = true;
    }
    if(icmp){
        if (addNextProtocol)
            str.append(" or ");
        str.append("icmp or icmp6");
    }
    str.append(")");
    return str;
}

/**
 * Ziska momentalni cas a ve spravnem formatu vraci.
 * @return Retezec, ve kterem je ulozen cas zachyceni paketu
 */
std::string time_rfc3339()
{
    char cstr[80];
    timeval curTime;
    gettimeofday(&curTime, NULL);
    int milli = curTime.tv_usec / 1000;
    char buffer [60];
    strftime(buffer,59,"%FT%T", localtime(&curTime.tv_sec));
    // %03d - vypis tri cela cisla
    sprintf(cstr, "%s.%03d+02:00", buffer, milli);
    std::string s(cstr);    // String s zalozen na zaklade pole cstr
    return s;
}

/**
 * Zpracovani a vypsani protokolu icmp pro ipv4.
 * Ze zacatku pretypovani paketu na ip strukturu, ziskani ip adres, vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka paketu
 * @param currentTime Cas obdrzeni paketu
 */
void icmp_v4(const u_char *packetWoEther,  const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime)
{
    printf("\n(ICMPv4)");
    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
    struct ip* iphdrVar = (struct ip*)packetWoEther; //pretypovani na IP hlavicku, ze ktere ziskame adresy
    std::string srcIpAddr = "";
    std::string destIpAddr = "";
    srcIpAddr.append(inet_ntoa(iphdrVar->ip_src));
    destIpAddr.append(inet_ntoa(iphdrVar->ip_dst));
    printf("\n%s %s > %s, length %d bytes\n", currentTime.c_str(), srcIpAddr.c_str(),
           destIpAddr.c_str(), lengthOfPacket);
    //print_packet_body(packet, lengthOfPacket);
}

/**
 * Zpracovani a vypsani protokolu icmp pro ipv6.
 * Ze zacatku pretypovani paketu na ip6 strukturu, ziskani ip adres, vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka paketu
 * @param currentTime Cas obdrzeni paketu
 */
void icmp_v6(const u_char *packetWoEther,  const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime)
{
    printf("\n(ICMPv6)");
    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
    struct ip6_hdr* ip6hdrVar = (struct ip6_hdr*)packetWoEther; //pretypovani na IP hlavicku, ze ktere ziskame adresy
    char srcIpAddr [INET6_ADDRSTRLEN];
    char destIpAddr [INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6hdrVar->ip6_src), srcIpAddr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6hdrVar->ip6_dst), destIpAddr, INET6_ADDRSTRLEN);
    printf("\n%s %s > %s, length %d bytes\n", currentTime.c_str(), srcIpAddr, destIpAddr, lengthOfPacket);
    //print_packet_body(packet, lengthOfPacket);
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
void udp_v4(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket,
              std::string currentTime, unsigned int ipLen)
{
    printf("\n(UDPv4)");
    // IP source/dest
    std::string srcIpAddr = "";
    std::string destIpAddr = "";
    // Pretypovani zbytku paketu na ip hlavicku
    struct ip *iphdrVar = (struct ip *) packetWoEther;
    srcIpAddr.append(inet_ntoa(iphdrVar->ip_src));
    destIpAddr.append(inet_ntoa(iphdrVar->ip_dst));
    const u_char *transportProtocolHdr = packet + ETH_HDR + ipLen;

    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/udp.h.html
    struct udphdr *udphdrVar = (struct udphdr *) transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(udphdrVar->uh_sport);
    uint16_t dstPort = ntohs(udphdrVar->uh_dport);
    printf("\n%s %s : %d > %s : %d, length %d bytes\n", currentTime.c_str(), srcIpAddr.c_str(), srcPort,
           destIpAddr.c_str(), dstPort, lengthOfPacket);
    //print_packet_body(packet, lengthOfPacket);
}

/**
 * Zpracovani a vypsani protokolu udp pro ipv6.
 * Ze zacatku pretypovani paketu na ip6 strukturu, pote ziskani ip adres,
 * posunuti se v paketu o delku hlavicky, pretypovani na upd strukturu,
 * zjisteni portu a nasledne vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka paketu
 * @param currentTime Cas obdrzeni paketu
 */
void udp_v6(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime)
{
    printf("\n(UDPv6)");
    // IP source/dest
    struct ip6_hdr* ip6hdrVar = (struct ip6_hdr*)packetWoEther; //pretypovani na IP hlavicku, ze ktere ziskame adresy
    char srcIpAddr [INET6_ADDRSTRLEN];
    char destIpAddr [INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6hdrVar->ip6_src), srcIpAddr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6hdrVar->ip6_dst), destIpAddr, INET6_ADDRSTRLEN);
    const u_char *transportProtocolHdr = packet + ETH_HDR + IPV6_HDR;

    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/udp.h.html
    struct udphdr *udphdrVar = (struct udphdr *) transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(udphdrVar->uh_sport);
    uint16_t dstPort = ntohs(udphdrVar->uh_dport);
    printf("\n%s %s : %d > %s : %d, length %d bytes\n", currentTime.c_str(), srcIpAddr, srcPort,
           destIpAddr, dstPort, lengthOfPacket);
    //print_packet_body(packet, lengthOfPacket);
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
void tcp_v4(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket,
              std::string currentTime, unsigned int ipLen)
{
    printf("\n(TCPv4)");
    // IP source/dest
    std::string srcIpAddr = "";
    std::string destIpAddr = "";
    // Pretypovani zbytku paketu na ip hlavicku
    struct ip* iphdrVar = (struct ip*)packetWoEther;
    srcIpAddr.append(inet_ntoa(iphdrVar->ip_src));
    destIpAddr.append(inet_ntoa(iphdrVar->ip_dst));
    const u_char *transportProtocolHdr = packet + ETH_HDR + ipLen;

    // https://unix.superglobalmegacorp.com/BSD4.4/newsrc/netinet/tcp.h.html
    struct tcphdr* tcphdrVar = (struct tcphdr*)transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(tcphdrVar->th_sport);
    uint16_t dstPort = ntohs(tcphdrVar->th_dport);
    printf("\n%s %s : %d > %s : %d, length %d bytes\n", currentTime.c_str(), srcIpAddr.c_str(), srcPort,
           destIpAddr.c_str(), dstPort, lengthOfPacket);
    //print_packet_body(packet, lengthOfPacket);
}

/**
 * Zpracovani a vypsani protokolu tcp pro ipv6.
 * Ze zacatku pretypovani paketu na ip6 strukturu, pote ziskani ip adres,
 * posunuti se v paketu o delku hlavicky, pretypovani na tcp strukturu,
 * zjisteni portu a nasledne vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka paketu
 * @param currentTime Cas obdrzeni paketu
 */
void tcp_v6(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime)
{
    printf("\n(TCPv6)");
    // IP source/dest
    struct ip6_hdr* ip6hdrVar = (struct ip6_hdr*)packetWoEther; //pretypovani na IP hlavicku, ze ktere ziskame adresy
    char srcIpAddr [INET6_ADDRSTRLEN];
    char destIpAddr [INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6hdrVar->ip6_src), srcIpAddr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6hdrVar->ip6_dst), destIpAddr, INET6_ADDRSTRLEN);
    const u_char *transportProtocolHdr = packet + ETH_HDR + IPV6_HDR;

    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/udp.h.html
    struct tcphdr* tcphdrVar = (struct tcphdr*)transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(tcphdrVar->th_sport);
    uint16_t dstPort = ntohs(tcphdrVar->th_dport);
    printf("\n%s %s : %d > %s : %d, length %d bytes\n", currentTime.c_str(), srcIpAddr, srcPort,
           destIpAddr, dstPort, lengthOfPacket);
    //print_packet_body(packet, lengthOfPacket);
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
    std::string currentTime = time_rfc3339();
    // Posunuti se v paketu o ethernetovou hlavicku
    const u_char *packetIP = packet + ETH_HDR;

    if(type == 0x0800){ //ipv4
        // Pretypovani zbytku paketu na ip hlavicku
        // https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html
        struct iphdr *ipHeader = (struct iphdr*)packetIP;

        // Podle protokolu se bude zpracovavat budto ICMP, TCP nebo UDP
        switch (ipHeader->protocol) {
            // ICMP
            case 1:
                icmp_v4(packetIP, packet, header->len, currentTime);
                break;

            // TCP + UDP
            case 6:
            case 17:{ // V zavorkach kvuli deklarovani promenne
                // Promenliva delka hlavicky
                unsigned int ipLen = ipHeader->ihl * 4;
                if(ipHeader->protocol == 17)
                    udp_v4(packetIP, packet, header->len, currentTime, ipLen);
                else
                    tcp_v4(packetIP, packet, header->len, currentTime, ipLen);
                break;
            }

            default:
                break;
        }
    }
    else if (type == 0x86DD){ // IPV6
        // https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html
        // Pretypovani zbytku paketu na ip hlavicku
        struct ip6_hdr *ip6Header = (struct ip6_hdr*)packetIP;

        // Podle protokolu se bude zpracovavat budto ICMP, TCP nebo UDP
        switch (ip6Header->ip6_nxt) {
            // ICMPv6
            case 58:
                icmp_v6(packetIP, packet, header->len, currentTime);
                break;

            // TCP
            case 6:
                tcp_v6(packetIP, packet, header->len, currentTime);
                break;

            // UDP
            case 17:
                udp_v6(packetIP, packet, header->len, currentTime);
                break;

            default:
                break;
        }
    }
    else if (type == 0x0806) {   // arp
        // https://unix.superglobalmegacorp.com/BSD4.4/newsrc/netinet/if_ether.h.html
        // Posunuti se v paketu o ethernetovou hlavicku
        //const u_char *packetArp = packet + ETH_HDR;
        struct ether_arp *etherArp = (struct ether_arp *) packetIP;

        // Ziskani source IP a MAC adresy
        struct in_addr *srcIP = (struct in_addr *) etherArp->arp_spa;
        char* srcMac = ether_ntoa((struct ether_addr*) &etherArp->arp_sha);
        std::string printAddr = ""; // retezec pro vypis adres
        // Format vypisu v podobe: sourceIP (sourceMac) > destIP (destMac)
        printAddr.append(inet_ntoa(*srcIP));
        printAddr.append(" (");
        printAddr.append(srcMac);
        printAddr.append(") > ");

        // Ziskani dest IP a MAC adresy
        struct in_addr *dstIP = (struct in_addr *) etherArp->arp_tpa;
        char *dstMac = ether_ntoa((struct ether_addr *) &etherArp->arp_tha);
        // Dovypsani
        printAddr.append(inet_ntoa(*dstIP));
        printAddr.append(" (");
        printAddr.append(dstMac);
        printAddr.append(")");

        std::string option;
        if (ntohs(etherArp->arp_op) == ARPOP_REQUEST)
            option = "requests";
        else if (ntohs(etherArp->arp_op) == ARPOP_REPLY)
            option = "reply";

        printf("%s %s (%s), length %d bytes\n", currentTime.c_str(), printAddr.c_str(), option.c_str(), header->len);
        //print_packet_body(packet, header->len);
    }
}

int main (int argc, char **argv)
{
    if (argc == 1){
        exit(1);
    }
    parse_arguments(argc, argv);


    struct bpf_program fp;
    // Hodnota pro filtrovani
    std::string filterStr = "";    // https://bit.ly/3giiyKP
    filterStr = fill_filter_str(filterStr);
    bpf_u_int32 net;
    

    pcap_t *handle;
    struct pcap_pkthdr header;
    const uint8_t *packet;
    char errbuf[PCAP_ERRBUF_SIZE];




    // Otevreni zarizeni pro sledovani paketu
    handle = pcap_open_offline(pcapFile_name.c_str(), errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERR]: Nepodařilo se mi otevřít zařízení %s: %s\n", device, errbuf);
        return(2);
    }
    while(packet = pcap_next(handle, &header))
    {
        printf("Got packet!");
    }
    // if (pcap_compile(handle, &fp, filterStr.c_str(), 0, net) == -1) {
    //     fprintf(stderr, "[ERR]: Parsování filtru se neydařilo %s: %s\n", filterStr.c_str(), pcap_geterr(handle));
    //     return(2);
    // }
    // if (pcap_setfilter(handle, &fp) == -1) {
    //     fprintf(stderr, "[ERR]: Filtr se nepodařilo uložit do pcap %s: %s\n", filterStr.c_str(), pcap_geterr(handle));
    //     return(2);
    // }
    // pcap_loop(handle, numOfPackets, process_packet, NULL);

    // pcap_freecode(&fp);
    pcap_close(handle);

    return(0);
}


/************************************
 * GLOBAL FUNCTIONS
 ************************************/