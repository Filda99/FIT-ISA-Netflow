#pragma once

#include "stdint.h"

struct flow_header
{
    uint16_t version = 5;           // NetFlow export format version number NetFlow export format version number
    uint16_t count = 1;             // Number of flows exported in this packet (1-30)
    uint16_t SysUpTime = 0;         // Current time in milliseconds since the export device booted
    uint32_t unix_secs = 0;         // Current count of seconds since 0000 UTC 1970
    uint32_t unix_nsecs = 0;        // Current count of nanoseconds since 0000 UTC 1970
    uint32_t flow_sequence = 0;     // Sequence counter of total flows seen
    uint8_t engine_type = 0;        // Type of flow-switching engine
    uint8_t engine_id = 0;          // Slot number of the flow-switching engine
    uint16_t sampling_interval = 0; // First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
};

struct flow_record
{
    uint32_t srcIP;       // Source IP address
    uint32_t dstIP;       // Destination IP address
    uint32_t nextHop;     // IP address of next hop router
    uint16_t scrIf = 0;   // SNMP index of input interface
    uint16_t dstIf = 0;   // SNMP index of output interface
    uint32_t dPkts = 0;   // Packets in the flow
    uint32_t dOctets = 0; // Total number of Layer 3 bytes in the packets of the flow
    uint32_t first = 0;   // SysUptime at start of flow
    uint32_t last = 0;    // SysUptime at the time the last packet of the flow was received
    uint16_t srcPort = 0; // TCP/UDP source port number or equivalent
    uint16_t dstPort = 0; // TCP/UDP destination port number or equivalent
    uint8_t pad1 = 0;     // Unused (zero) bytes
    uint8_t flgs = 0;     // Cumulative OR of TCP flags
    uint8_t prot = 0;     // IP protocol type
    uint8_t tos = 0;      // IP type of service (ToS)
    uint16_t srcAs = 0;   // Autonomous system number of the source, either origin or peer
    uint16_t dstAs = 0;   // Autonomous system number of the destination, either origin or peer
    uint8_t srcMask = 32; // Source address prefix mask bits
    uint8_t dstMask = 32; // Destination address prefix mask bits
    uint16_t pad2 = 0;    // Unused (zero) bytes
};

struct flow
{
    flow_header header;
    flow_record body;
};