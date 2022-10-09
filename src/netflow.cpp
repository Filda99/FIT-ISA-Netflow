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
 * ./flow [-f <file>] [-c <netflow_collector_>[:<port>]] [-a <active_timer_>] [-i <inactive_timer_>] [-m <count>]
 *      - f <file> - jméno analyzovaného souboru nebo STDIN
 *      - c <neflow_collector:port> - IP adresa, nebo hostname NetFlow kolektoru. Volitelně i UDP port
 *      - a <active_timer_> - interval v sekundách, po kterém se exportují aktivní záznamy na kolektor
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
#include <algorithm>
#include <vector>
#include<ctime>


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
struct flow_header {
    uint16_t version = 5;       // NetFlow export format version number NetFlow export format version number 
    uint16_t count = 0;         // Number of flows exported in this packet (1-30) 
    uint16_t SysUpTime = 0;     // Current time in milliseconds since the export device booted 
    uint32_t unix_secs = 0;     // Current count of seconds since 0000 UTC 1970 
    uint32_t unix_nsecs = 0;    // Current count of nanoseconds since 0000 UTC 1970 
    uint32_t flow_sequence = 0; // Sequence counter of total flows seen 
    uint8_t  engine_type = 0;   // Type of flow-switching engine 
    uint8_t  engine_id = 0;     // Slot number of the flow-switching engine 
    uint16_t sampling_interval = 0; // First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
};

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

struct flow {
   flow_header header;
   flow_record body; 
};

/************************************
 * GLOBAL VARIABLES
 ************************************/
string pcapFile_name_ = "-";
string netflow_collector_ = "127.0.0.1:2055";
int active_timer_ = 60;
int inactive_timer_ = 10;
int flowcache_size_ = 1024;
map< tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>, flow >flow_map_;
uint32_t time_now_;
vector<flow> sending_packets_;

/************************************
 * STATIC FUNCTION PROTOTYPES
 ************************************/
void parse_arguments(int argc, char **argv);
tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> create_key(flow flow);
bool compare_by_times(const flow &a, const flow &b);
void check_timers();
void send_flows();
void update_flow_record(flow existingRecord, flow newRecord);

void icmp_v4(flow flow);
void udp_v4(flow flow, const u_char *transportProtocolHdr);
void tcp_v4(flow flow, const u_char *transportProtocolHdr);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


/************************************
 * STATIC FUNCTIONS
 ************************************/

/************************************
 * Arguments
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
                pcapFile_name_ = optarg;
                break;

            case 'c':
                netflow_collector_ = optarg;
                break;

            case 'a':
                if ((active_timer_ = atoi(optarg)) == 0){
                    fprintf(stderr, "[ERR]: Parametru -a lze priradit pouze int.\n");
                    exit(3);
                }
                break;

            case 'i':
                if ((inactive_timer_ = atoi(optarg)) == 0){
                    fprintf(stderr, "[ERR]: Parametru -i lze priradit pouze int.\n");
                    exit(3);
                }
                break;

            case 'm':
                if ((flowcache_size_ = atoi(optarg)) == 0){
                    fprintf(stderr, "[ERR]: Parametru -m lze priradit pouze int.\n");
                    exit(3);
                }
                break;

            default:
                break;
        }
    }
}


tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> create_key(flow flow)
{
    // srcIP, dstIP, srcPort, dstPort, protocol
    tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> key = 
        make_tuple(flow.body.srcIP, flow.body.dstIP, flow.body.srcPort, flow.body.dstPort, flow.body.prot);
    return key;
}

/************************************
 * Helping
 ************************************/
bool compare_by_times(const flow &a, const flow &b)
{
    return a.header.SysUpTime > b.header.SysUpTime;
}

void check_timers()
{
    cout << "Flow map has these items:" << endl;
    for (auto itr = flow_map_.begin(); itr != flow_map_.end(); itr++)
    {
        cout << " - " << itr->second.body.srcIP << endl;
        // Active
        uint32_t atimer = time_now_ - itr->second.body.first;

        // Inactive
        uint32_t itimer = time_now_ - itr->second.body.last;

        if (atimer < active_timer_ && itimer < inactive_timer_)
        {
            continue;
        }

        // Both timer run out
        if (atimer > active_timer_ && itimer > inactive_timer_)
        {
            // We need to select, which one is older
            atimer = atimer - active_timer_;
            itimer = itimer - inactive_timer_;
            if (atimer > itimer)
            {
                //uint32_t overlappingTime = time_now_ % itr->second.body.last;
                itr->second.header.SysUpTime = itr->second.body.first + atimer;
            }
            else
            {
                itr->second.header.SysUpTime = itr->second.body.last + itimer;
            }
        }
        // Active timer run out
        else if (atimer > active_timer_)
        {
            itr->second.header.SysUpTime = itr->second.body.first + atimer;
        }
        // Inactive timer run out
        else if (itimer > inactive_timer_)
        {
            itr->second.header.SysUpTime = itr->second.body.last + itimer;
        }
        sending_packets_.push_back(itr->second);
    }
    if(!sending_packets_.empty())
    {
        send_flows();
    }
}


/************************************
 * Flows
 ************************************/
void send_flows()
{
    sort(sending_packets_.begin(), sending_packets_.end(), compare_by_times);

    while (!sending_packets_.empty())
    {
        flow packet = sending_packets_.back();
        tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> key = 
            make_tuple(packet.body.srcIP, packet.body.dstIP, packet.body.srcPort, packet.body.dstPort, packet.body.prot);
            
        flow_map_.erase(key);
        sending_packets_.pop_back();

        cout << "Sending packet: ";
        cout << packet.body.srcIP << endl;
    }

    cout << "..." << endl;
    // TODO: send packets
}


void update_flow_record(flow existingRecord, flow newRecord)
{
    existingRecord.body.dOctets += newRecord.body.dOctets;
    existingRecord.body.dPkts++;
    existingRecord.body.last = newRecord.body.first;
}


/************************************
 * Packets
 ************************************/
/**
 * Zpracovani a vypsani protokolu icmp pro ipv4.
 * Ze zacatku pretypovani paketu na ip strukturu, ziskani ip adres, vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka paketu
 * @param currentTime Cas obdrzeni paketu
 */
void icmp_v4(flow flow)
{
    auto key = create_key(flow);
    
    check_timers();

    // TODO: find in a map -> flow_map_[keys] = flow;
    // TODO: print first arg in tuple -> cout << get<0>(key);
    if(flow_map_.find(key)!= flow_map_.end()){
        struct flow existingRecord = flow_map_[key];
        cout << "Existint item found! " << existingRecord.body.srcIP << endl;
        update_flow_record(existingRecord, flow);
    }
    else{
        flow_map_[key] = flow;
        cout << "Adding new item: " << flow.body.srcIP << endl;
    }
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
void udp_v4(flow flow, const u_char *transportProtocolHdr)
{
    struct udphdr *udpHdr = (struct udphdr *) transportProtocolHdr; // udp struktura
    flow.body.srcPort = ntohs(udpHdr->uh_sport);
    flow.body.dstPort = ntohs(udpHdr->uh_dport);

    auto key = create_key(flow);
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
void tcp_v4(flow flow, const u_char *transportProtocolHdr)
{
    struct tcphdr* tcpHdr = (struct tcphdr*)transportProtocolHdr; // udp struktura
    flow.body.srcPort = ntohs(tcpHdr->th_sport);
    flow.body.dstPort = ntohs(tcpHdr->th_dport);
    flow.body.flgs = tcpHdr->th_flags; 

    auto key = create_key(flow);
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
    flow flow;

    struct ether_header *ipvNum = (struct ether_header*)packet;
    u_short type = ntohs(ipvNum->ether_type);

    // Posunuti se v paketu o ethernetovou hlavicku
    const u_char *packetIP = packet + ETH_HDR;
    struct ip *ipHeader = (struct ip*)packetIP;
    time_t rawtime = header->ts.tv_sec;
    printf ("The packet time is: %s\n", ctime (&rawtime));

    if(type == 0x0800){ //ipv4
        flow.body.prot = ipHeader->ip_p;
        flow.body.tos = ipHeader->ip_tos;
        flow.body.srcIP = ipHeader->ip_src.s_addr;
        flow.body.dstIP = ipHeader->ip_dst.s_addr;
        flow.body.first = header->ts.tv_sec;
        // flow.body.first = flow.header.SysUpTime - flow.body.first;
        time_t time = flow.body.first;
        suseconds_t times = header->ts.tv_usec;
        printf ("The packet seconds are: %s\n", ctime (&time));
        printf ("The packet useconds are: %s\n", ctime (&times));

        // time_t tmPacket = header->ts.tv_usec;
        // struct tm t = *localtime(&tmPacket);;
        // cout<<"Current Date: "<<t.tm_year+1900<<"-"<<t.tm_mon+1<<"-"<< t.tm_mday<< endl;
        // cout<<"Current Time: "<<t.tm_hour<<":"<<t.tm_min<<":"<<t.tm_sec << endl;

        switch (ipHeader->ip_p) {
            // ICMP
            case 1:
                icmp_v4(flow);
                break;

            // TCP + UDP
            case 6:
            case 17:{ // V zavorkach kvuli deklarovani promenne
                // Promenliva delka hlavicky
                flow.body.dOctets = ipHeader->ip_hl * 4;
                const u_char *transportProtocolHdr = packet + ETH_HDR + flow.body.dOctets;

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
    handle = pcap_open_offline(pcapFile_name_.c_str(), errbuf);
    if (handle == NULL) {
        fprintf(stderr, "[ERR]: Nepodařilo se mi otevřít soubor %s, %s\n",pcapFile_name_.c_str(), errbuf);
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
