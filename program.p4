#include <core.p4>
#include <v1model.p4>

#define OUT_PORT 2
#define MAX_ADDRESS 32w4194304
#define PKT_THRESHOLD 32w5
#define DAY_THRESHOLD 32w1

// Two weeks
#define TIMEOUT 48w1209600000000
#define DAY 48w86400000000

const bit<16> TYPE_IPV4 = 0x800;

register<bit<32>>(MAX_ADDRESS) pkt;
register<bit<48>>(MAX_ADDRESS) timestamp;
register<bit<32>>(MAX_ADDRESS) days;
// First timestamp of the day
register<bit<48>>(32w1) day_start;
register<bit<1>>(32w1) attack; // Indicates whether an attack is happening or not

// Headers

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
}

// Parser

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w0x6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

// Checksum verification

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}

// Ingress pipeline

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action get_data(inout bit<32> address ,inout bit<32> num_packets, inout bit<48> ts, inout bit<32> num_days) {
        hash(address,
             HashAlgorithm.crc32,
             32w0,
             { hdr.ipv4.srcAddr },
             MAX_ADDRESS);
        // Read the files in the registers
        pkt.read(num_packets, address);
        timestamp.read(ts, address);
        days.read(num_days, address);
    }

    action sliding_window(inout bit<32> num_packets, in bit<48> ts, inout bit<32> num_days) {
        // Sliding window
        if (standard_metadata.ingress_global_timestamp - ts > TIMEOUT) {
            num_packets = 0;
            num_days = 0;
        }
    }

    action update_hashtable(inout bit<32> address, inout bit<32> num_packets, inout bit<48> ts, inout bit<32> num_days) {
        bit<48> cur_time = standard_metadata.ingress_global_timestamp;
        bit<48> ds; // Start of the day
        day_start.read(ds, 32w0);
        if (ts < ds || ts == 0) { // Last seen was before today or not seen before
            num_days = num_days + 1;
        }
        num_packets = num_packets + 1;

        // Write new values to the registers
        pkt.write(address, num_packets);
        timestamp.write(address, cur_time);
        days.write(address, num_days);
    }

    apply {
        standard_metadata.egress_spec = OUT_PORT; // Forward all packets to h2
        // Set initial day
        bit<48> ds;
        day_start.read(ds,32w0);
        if (ds == 0) {
            ds = standard_metadata.ingress_global_timestamp;
            day_start.write(32w0,standard_metadata.ingress_global_timestamp);
        }
        bit<1> flag;
        bit<32> num_packets = 0;
        bit<48> ts = 0; // Time stamp
        bit<32> num_days = 0;
        bit<32> address = 0;
        get_data(address, num_packets,ts,num_days);
        attack.read(flag, 0);
        // Check if under attack
        if (flag == 1w1) {
            // Sliding_window(num_packets, ts, num_days);
            if (num_packets < PKT_THRESHOLD || num_days < DAY_THRESHOLD) {
                drop();
            }
        } else {
            update_hashtable(address, num_packets,ts,num_days);
        }
        // Update start of the day
        if (standard_metadata.ingress_global_timestamp - ds > DAY) { // One day
            day_start.write(32w0,standard_metadata.ingress_global_timestamp); // A new day has started
        }
    }

}

// Egress pipeline

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { 
        hdr.ethernet.etherType = TYPE_IPV4;
    }
}

// Checksum computation

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

// Deparser

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

// Switch

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
