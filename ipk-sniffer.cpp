/*********************************************************************************************************************
 * Předmět:     Počítačové komunikace a sítě
 * Projekt:     Sniffer packetů
 * Datum:       4/2021
 * Vypracoval:  Filip Jahn
 * Login:       xjahnf00
 *
 * *******************************************************************************************************************
 * Zadání:
 * Navrhněte a implementujte síťový analyzátor v C/C++/C#,
 * který bude schopný na určitém síťovém rozhraním zachytávat a filtrovat pakety.
 *
 * *******************************************************************************************************************
 * Spuštění:
 * ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
 * -> Složené závorky {} znamenají, že volba je nepovinná, oproti tomu [] znamená povinnou volbu.
 *      -i eth0 (právě jedno rozhraní, na kterém se bude poslouchat)
 *      -p 23 (bude filtrování paketů na daném rozhraní podle portu)
 *      -t nebo --tcp (bude zobrazovat pouze TCP pakety)
 *      -u nebo --udp (bude zobrazovat pouze UDP pakety)
 *      --icmp (bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)
 *      --arp (bude zobrazovat pouze ARP rámce)
 *      -> Pokud nebudou konkrétní protokoly specifikovány, uvažují se k tisknutí všechny
 *      -n 10 (určuje počet paketů, které se mají zobrazit)
 *
 * *******************************************************************************************************************
 */

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

#define ETH_HDR  14
//#define IPV4_PROT   0
//#define IPV6_PROT   1
#define IPV6_HDR    40

/***********************/
/** Globalni promenne **/
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
/***********************/

/**
 * Vypsani rozhranni, na kterych se da packety odchytavat.
 */
void print_interface()
{
    // Prevzato a upraveno z: http://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;
    if(pcap_findalldevs(&interfaces,error)==-1)
    {
        printf("[ERR]: Nenasel jsem zadna zarizeni.\n");
    }
    printf("Seznam veskerych rozhranni je nasledujici:\n");
    for(temp=interfaces;temp;temp=temp->next)
    {
        printf("%d:  %s\n",i++,temp->name);
    }
    exit(1);
}

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

    static struct option longOpts[] =
        {
                {"interface",   required_argument,  0,  'i'},
                {"tcp",         no_argument,        0,  't'},
                {"udp",         no_argument,        0,  'u'},
                {"arp",         no_argument,        0,  0},
                {"icmp",        no_argument,        0,  0},
                {0, 0, 0, 0}  // ukoncovaci prvek
        };

    int c;          // Prave nacteny argument
    int index = 0;  //  Index ve strukture longOpts, vyuziva se, kdyz argument nema zkratku
    //  interface, port, num musi pozaduji zadane argumenty
    while((c = getopt_long(argc, argv, ":i:p:tun:", longOpts, &index)) != -1){
        //printf("%c\n", c);
        switch (c)
        {
            // Pokud je zadan pouze samotny argument, napr: -i
            case ':':
                if (optopt == 'i'){
                    print_interface();
                }
                else{
                    fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
                    exit(3);
                }
            case 0:
                if (longOpts[index].flag != 0)
                    break;
                if (strcmp(longOpts[index].name, "arp") == 0)
                    arp = true;
                else if (strcmp(longOpts[index].name, "icmp") == 0)
                    icmp = true;
                else{
                    fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
                    exit(3);
                }
                break;
            case 'i':
                if (optarg == NULL || (strcmp(optarg, "-p") == 0)){
                    fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
                    exit(3);
                }
                else{
                    device = optarg;
                    checkInterface = true;
                }
                break;

            case 'p':
                if (atoi(optarg) < 0){
                    fprintf(stderr, "[ERR]: Parametru -p lze priradit pouze int.\n");
                    exit(3);
                }
                else{
                    port = optarg;
                }
                break;

            case 't':
                tcp = true;
                break;

            case 'u':
                udp = true;
                break;

            case 'n':
                if ((numOfPackets = atoi(optarg)) == 0){
                    fprintf(stderr, "[ERR]: Parametru -n lze priradit pouze int.\n");
                    exit(3);
                }
                break;

            default:
                fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
                exit(3);
        }
    }
    if (!checkInterface){
        fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
        exit(3);
    }

    if (!tcp && !udp && !arp && !icmp){
        tcp = true;
        udp = true;
        arp = true;
        icmp = true;
    }
    return;
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
 * Vypsani prave casti vypisu v ascii podobe.
 * Pokud nejsou znaky tisknutelne, vypiseme misto nich tecku.
 * @param asciiStr Pole znaku jednoho radku (max 16 znaku + \O), ktere se maji vypsat
 * @param charsToPrint Kolik se ma vypsat znaku (cely radek nebo jen cast)
 */
void print_char_ascii(char asciiStr[17], int charsToPrint)
{
    printf("\t");
    for(int i = 0; i < charsToPrint; i++){
        if(i == 8)
            printf(" ");
        if (isprint(asciiStr[i]))
            printf("%c", asciiStr[i]);
        else
            printf(".");
    }
}

/**
 * Funkce pro vypis dat z paketu.
 * Prochazeni dat z paketu, kde kazdy znak vypisujeme v hexa podobe a ukladame
 * do pole asciiStr dany znak pro pozdejsi vypsani ve funkci print_char_ascii().
 * @param packet Prijaty paket, ktery se ma vypsat
 * @param length Delka paketu. Prochazime ho od zacatku do konce
 */
void print_packet_body( const u_char *packet, bpf_u_int32 length)
{
    char asciiStr[17] = "";
    int posInPckt;

    // Vypis celych radku
    for (posInPckt = 0; posInPckt < length; posInPckt++){
        int lastPosInLine = (posInPckt % 16);
        // Vypis konec radku, ascii hodnoty
        if(lastPosInLine == 0 && posInPckt != 0){
            print_char_ascii(asciiStr, 16); // Vypis cely radek = 16 znaku
        }

        // Vypis zacatku radku
        if(lastPosInLine == 0){// End of line
            // Nechceme aby se nam oddelil prvni radek od vypisu dat
            if (posInPckt != 0)
                printf("\n");
            int line_number = posInPckt / 16;
            // New line
            printf("0x%03d0\t", line_number);
        }

        // Mezera uprostred
        if ((posInPckt % 8) == 0)
            printf(" ");

        // Vypis dat v hexa podobe
        printf("%02x ", packet[posInPckt]);
        asciiStr[lastPosInLine] = packet[posInPckt];
    }

    // Vypis posledniho radku (uz pouze ascii) - zpravidla jen cast radku

    int charsToPrint = posInPckt % 16;  // Pocet znaku ascii, ktere se maji vypsat
    // Zarovnani na konec
    while((posInPckt % 16) != 0){
        printf("   ");
        posInPckt++;
    }
    // Vypsani ascii hodnot
    print_char_ascii(asciiStr, charsToPrint); // Vypis takovy pocet znaku, kolik je na poslednim radku

    printf("\n");
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
    print_packet_body(packet, lengthOfPacket);
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
    print_packet_body(packet, lengthOfPacket);
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
    print_packet_body(packet, lengthOfPacket);
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
    print_packet_body(packet, lengthOfPacket);
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
    print_packet_body(packet, lengthOfPacket);
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
    print_packet_body(packet, lengthOfPacket);
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
        print_packet_body(packet, header->len);
    }
}

int main (int argc, char **argv)
{
    if (argc == 1){
        print_interface();
        exit(1);
    }
    // Parsovani argumentu
    parse_arguments(argc, argv);

    pcap_t *handle;
    struct bpf_program fp;
    // Hodnota pro filtrovani
    std::string filterStr = "";    // https://bit.ly/3giiyKP
    filterStr = fill_filter_str(filterStr);
    bpf_u_int32 net;
    // Error buffer, slouzi pro ukladani pripadnych erroru
    char errbuf[PCAP_ERRBUF_SIZE];

    // Otevreni zarizeni pro sledovani paketu
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERR]: Nepodařilo se mi otevřít zařízení %s: %s\n", device, errbuf);
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
    pcap_loop(handle, numOfPackets, process_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return(0);
}