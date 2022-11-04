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
#include <arpa/inet.h> //inet_ntoa(), inet_ntop()
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>  //icmp hlavicka
#include <netinet/udp.h>      //udp hlavicka
#include <netinet/tcp.h>      //tcp hlavicka
#include <netinet/if_ether.h> //ethernet hlavicka
#include <netinet/ip.h>       //ip hlavicka
#include <math.h>
#include <map>
#include <tuple>
#include <algorithm>
#include <vector>
#include <time.h>
#include "send_data.h"
#include "globals.h"

using namespace std;
/************************************
 * EXTERN VARIABLES
 ************************************/

/************************************
 * PRIVATE MACROS AND DEFINES
 ************************************/
#define ETH_HDR 14

/************************************
 * PRIVATE TYPEDEFS
 ************************************/

/************************************
 * GLOBAL VARIABLES
 ************************************/
string pcapFile_name_ = "-";
string netflow_collector_ip_ = "127.0.0.1";
string netflow_collector_port_ = "2055";
int active_timer_ = 60;
int inactive_timer_ = 10;
int flowcache_size_ = 1024;
map<tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t>, flow> flow_map_;
timeval time_now_{};
timeval time_first_pkt{};
vector<flow> sending_packets_;

/************************************
 * STATIC FUNCTION PROTOTYPES
 ************************************/
void parse_arguments(int argc, char **argv);
tuple<uint32_t, uint32_t, uint16_t, uint16_t, uint8_t> create_key(flow flow);
uint32_t getMillis(timeval ts);
bool compare_by_times(const flow &a, const flow &b);
void check_timers();
void send_flows(int howMany);
void edit_flow(struct flow *flow);
void update_flow_record(flow *existingRecord, flow *newRecord);

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
    while ((c = getopt(argc, argv, "f:c:a:i:m:")) != -1)
    {
        switch (c)
        {
        case 'f':
            pcapFile_name_ = optarg;
            break;

        case 'c':
        {
            string netflow_collector = optarg;
            size_t found;
            if ((found = netflow_collector.find(":")) != string::npos)
            {
                netflow_collector_ip_ = netflow_collector.substr(0, found);
                netflow_collector_port_ = netflow_collector.substr(found + 1, string::npos);
            }
                
            break;
        }
            
        case 'a':
            if ((active_timer_ = atoi(optarg)) == 0)
            {
                fprintf(stderr, "[ERR]: Parametru -a lze priradit pouze int.\n");
                exit(3);
            }
            break;

        case 'i':
            if ((inactive_timer_ = atoi(optarg)) == 0)
            {
                fprintf(stderr, "[ERR]: Parametru -i lze priradit pouze int.\n");
                exit(3);
            }
            break;

        case 'm':
            if ((flowcache_size_ = atoi(optarg)) == 0)
            {
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
uint32_t getMillis(timeval ts) 
{
    return ts.tv_sec * 1000 + round(ts.tv_usec) / 1000;
}

bool compare_by_times(const flow &a, const flow &b)
{
    return a.body.last < b.body.last;
}

void check_timers()
{
    if (flow_map_.empty())
    {
        return;
    }

    for (auto itr = flow_map_.begin(); itr != flow_map_.end(); itr++)
    {
        timeval flow_SysUpTime{};
        // struct timeval flow_time {(long int)&itr->second.header.unix_secs, (long int)&itr->second.header.unix_nsecs};
        timersub(&time_now_, &time_first_pkt, &flow_SysUpTime);

        uint32_t active_time = getMillis(flow_SysUpTime) - itr->second.body.first;
        uint32_t inactive_time = getMillis(flow_SysUpTime) - itr->second.body.last;

        if (active_time < (active_timer_ * 1000) && inactive_time < (inactive_timer_ * 1000))
        {
            continue;
        }

        // Both timer run out
        if (active_time > (active_timer_ * 1000) && inactive_time > (inactive_timer_ * 1000))
        {
            // We need to select, which one is older
            active_time = active_time - active_timer_;
            inactive_time = inactive_time - inactive_timer_;
            if (active_time > inactive_time)
            {
                itr->second.header.SysUpTime = itr->second.body.first + active_timer_*1000;
                itr->second.header.unix_secs = itr->second.header.unix_secs + active_timer_;
            }
            else
            {
                itr->second.header.SysUpTime = itr->second.body.last + inactive_timer_*1000;
                itr->second.header.unix_secs = itr->second.header.unix_secs + inactive_timer_;
            }
        }
        // Active timer run out
        else if (active_time > (active_timer_ * 1000))
        {
            itr->second.header.SysUpTime = itr->second.body.first + active_timer_*1000;
            itr->second.header.unix_secs = itr->second.header.unix_secs + active_timer_;
        }
        // Inactive timer run out
        else if (inactive_time > (inactive_timer_ * 1000))
        {
            itr->second.header.SysUpTime = itr->second.body.last + inactive_timer_*1000;
            itr->second.header.unix_secs = itr->second.header.unix_secs + inactive_timer_;
        }

        itr->second.header.unix_nsecs = flow_SysUpTime.tv_usec * 1000;

        sending_packets_.push_back(itr->second);
    }

    if (!sending_packets_.empty())
    {
        send_flows(-1);
    }
}


/************************************
 * Flows
 ************************************/
void send_flows(int howMany)
{
    static int flows_send = 0;
    sort(sending_packets_.begin(), sending_packets_.end(), compare_by_times);

    int cycleCounter = 0;
    while (!sending_packets_.empty())
    {
        cycleCounter++;
        flow packet = sending_packets_.back();
        auto key = create_key(packet);

        flow_map_.erase(key);
        sending_packets_.pop_back();
        
        packet.header.flow_sequence = flows_send++;
        // packet.header.unix_secs = time_now_.tv_sec;
        // packet.header.unix_nsecs = time_now_.tv_usec * 1000;

        // timeval sysUpTime;
        // timersub(&time_now_, &time_first_pkt, &sysUpTime);
        // packet.header.SysUpTime = getMillis(sysUpTime);
        
        edit_flow(&packet);
        send_data(packet);

        if (howMany == cycleCounter)
            return;
    }
}


void create_flow(flow *flow)
{
    timeval sysUpTime;
    timersub(&time_now_, &time_first_pkt, &sysUpTime);
    flow->header.SysUpTime = getMillis(sysUpTime);
    flow->body.first = flow->header.SysUpTime;
    flow->body.last = flow->header.SysUpTime;

    flow->header.unix_secs = time_now_.tv_sec;
    flow->header.unix_nsecs = time_now_.tv_usec * 1000;
}


void update_flow_record(flow *existingRecord, flow *newRecord)
{
    timeval sysUpTime;
    timersub(&time_now_, &time_first_pkt, &sysUpTime);
    existingRecord->header.SysUpTime = getMillis(sysUpTime);
    existingRecord->body.last = existingRecord->header.SysUpTime;

    existingRecord->header.unix_secs = time_now_.tv_sec;
    existingRecord->header.unix_nsecs = time_now_.tv_usec * 1000;

    existingRecord->body.dOctets += newRecord->body.dOctets;
    existingRecord->body.dPkts++;
}


void edit_flow(struct flow *flow)
{
    flow->header.version = ntohs(flow->header.version);
    flow->header.count = ntohs(flow->header.count);
    flow->header.SysUpTime = ntohl(flow->header.SysUpTime);
    flow->header.unix_nsecs = ntohl(flow->header.unix_nsecs);
    flow->header.unix_secs = ntohl(flow->header.unix_secs);

    flow->body.dOctets = ntohl(flow->body.dOctets);
    flow->body.dPkts = ntohl(flow->body.dPkts);
    flow->body.dstAs = ntohs(flow->body.dstAs);
    flow->body.dstIf = ntohs(flow->body.dstIf);
    flow->body.dstPort = ntohs(flow->body.dstPort);
    flow->body.first = ntohl(flow->body.first);
    flow->body.last = ntohl(flow->body.last);
    flow->body.nextHop = ntohl(flow->body.nextHop);
    flow->body.scrIf = ntohs(flow->body.scrIf);
    flow->body.srcAs = ntohs(flow->body.srcAs);
    flow->body.srcPort = ntohs(flow->body.srcPort);
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
    auto it = flow_map_.find(key);

    if (it != flow_map_.end())
    {
        update_flow_record(&it->second, &flow);
    }
    else
    {
        if ((flow_map_.size() + 1) > flowcache_size_)
        {
            send_flows(1);
        }
        create_flow(&flow);
        flow_map_[key] = flow;
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
    struct udphdr *udpHdr = (struct udphdr *)transportProtocolHdr; // udp struktura
    flow.body.srcPort = ntohs(udpHdr->uh_sport);
    flow.body.dstPort = ntohs(udpHdr->uh_dport);

    auto key = create_key(flow);
    auto it = flow_map_.find(key);

    if (it != flow_map_.end())
    {
        update_flow_record(&it->second, &flow);
    }
    else
    {
        if ((flow_map_.size() + 1) > flowcache_size_)
        {
            send_flows(1);
        }
        create_flow(&flow);
        flow_map_[key] = flow;
    }
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
    struct tcphdr *tcpHdr = (struct tcphdr *)transportProtocolHdr; // udp struktura
    flow.body.srcPort = ntohs(tcpHdr->th_sport);
    flow.body.dstPort = ntohs(tcpHdr->th_dport);
    flow.body.flgs = tcpHdr->th_flags;

    auto key = create_key(flow);
    auto it = flow_map_.find(key);
 
    if (it != flow_map_.end())
    {
        update_flow_record(&it->second, &flow);
    }
    else
    {
        if ((flow_map_.size() + 1) > flowcache_size_)
        {
            send_flows(1);
        }
        create_flow(&flow);
        flow_map_[key] = flow;
    }
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

    struct ether_header *ipvNum = (struct ether_header *)packet;
    u_short type = ntohs(ipvNum->ether_type);

    // Posunuti se v paketu o ethernetovou hlavicku
    const u_char *packetIP = packet + ETH_HDR;
    struct ip *ipHeader = (struct ip *)packetIP;
    static int flows_count = 0;

    if (type == 0x0800)
    { // ipv4
        time_now_ = header->ts;
        if (flows_count == 0)
        {
            time_first_pkt = time_now_;
        }
        flows_count++;

        flow.body.prot = ipHeader->ip_p;
        flow.body.tos = ipHeader->ip_tos;
        flow.body.srcIP = ipHeader->ip_src.s_addr;
        flow.body.dstIP = ipHeader->ip_dst.s_addr;
        flow.body.dOctets = htons(ipHeader->ip_len);

        // Check timers, if some packets in map should be send to collector. 
        check_timers();

        switch (ipHeader->ip_p)
        {
        // ICMP
        case 1:
            icmp_v4(flow);
            break;

        // TCP + UDP
        case 6:
        case 17:
        {
            unsigned int ipLen = ipHeader->ip_hl * 4;
            const u_char *transportProtocolHdr = packet + ETH_HDR + ipLen;

            if (ipHeader->ip_p == 17)
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

    if (pcap_compile(handle, &fp, filterStr.c_str(), 0, net) == -1)
    {
        fprintf(stderr, "[ERR]: Parsování filtru se neydařilo %s: %s\n", filterStr.c_str(), pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "[ERR]: Filtr se nepodařilo uložit do pcap %s: %s\n", filterStr.c_str(), pcap_geterr(handle));
        return (2);
    }
    return 1;
}

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        exit(1);
    }
    parse_arguments(argc, argv);

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    create_connection((char*)netflow_collector_ip_.c_str(), 
        (char*)netflow_collector_port_.c_str());

    handle = pcap_open_offline(pcapFile_name_.c_str(), errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "[ERR]: Nepodařilo se mi otevřít soubor %s, %s\n", pcapFile_name_.c_str(), errbuf);
        return (2);
    }

    if (pcap_set_filter(handle) != 1)
    {
        pcap_close(handle);
        return (2);
    }

    pcap_loop(handle, 0, process_packet, NULL);

    while (!flow_map_.empty())
    {
        time_now_.tv_sec++;
        check_timers();
    }

    pcap_close(handle);

    close_connection();

    return (0);
}
