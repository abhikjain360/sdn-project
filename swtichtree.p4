#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

const bit<48> ACTIVE_FLOW_THRESHOLD = 5000000; // in microseconds
const bit<48> FLOW_THRESHOLD = 120000000; // in microseconds
const bit<48> MALICIOUS_TIMEOUT = 600000000; // in microseconds

const bit<2> MALWARE_FLAG = 0b11;
const bit<2> BENIGN_FLAG = 0b10;

const bit<16> NO_FEATURE = 1024;


#define BLOOM_FILTER_ENTRIES 4096

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

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
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
	tcp_t 	   tcp;
}

struct metadata {
	// the index in registers where current flow stats are located
	bit<32> flow_pos;

	// flag counters
	bit<16> psh_flag_count;
	bit<16> syn_flag_count;
	bit<16> ack_flag_count;
	bit<32> total_packets;

	// lengths
	bit<32> total_length_of_packets;
	bit<32> total_length_of_fwd_packets;
	bit<32> init_win_byte_forward;

	// timestamps
	bit<48> active_flow_start_timestamp;
	bit<48> flow_start_timestamp;
	bit<48> last_seen;
	bit<48> last_malicous_classified; // only valid if malicious_flow == 1

	// durations
	bit<48> flow_duration;
	bit<48> active_min;
	bit<48> flow_iat_min;

	// flow identification
	bit<32> init_src_addr;
	bit<32> init_dst_addr;
	bit<1>  known_flow;
	bit<1> malicious_flow;

	// for making final decision
	bit<1> 	feature_less_than_threshold;
	bit<16> previous_feature;

	// the final decision
	bit<16> total_value;
	bit<1> stop_traversal;

	// for matching
	bit<16> node_id;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/


parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
	state start {
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select (hdr.ethernet.etherType) {
			TYPE_IPV4: parse_ipv4;
			default:   accept;
		}
	}

	state parse_ipv4 {
		packet.extract(hdr.ipv4);
		transition select (hdr.ipv4.protocol) {
			TYPE_TCP: parse_tcp;
			default: accept;
		}
	}

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition accept;
	}
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

	// flag counts
	register<bit<16>>(BLOOM_FILTER_ENTRIES) psh_flag_count;
	register<bit<16>>(BLOOM_FILTER_ENTRIES) syn_flag_count;
	register<bit<16>>(BLOOM_FILTER_ENTRIES) ack_flag_count;
	register<bit<32>>(BLOOM_FILTER_ENTRIES) total_packets;

	// lengths
	register<bit<32>>(BLOOM_FILTER_ENTRIES) total_length_of_packets;
	register<bit<32>>(BLOOM_FILTER_ENTRIES) total_length_of_fwd_packets;
	register<bit<32>>(BLOOM_FILTER_ENTRIES) init_win_byte_forward;

	// timestamps
	register<bit<48>>(BLOOM_FILTER_ENTRIES) flow_start_timestamp;
	register<bit<48>>(BLOOM_FILTER_ENTRIES) active_flow_start_timestamp;
	register<bit<48>>(BLOOM_FILTER_ENTRIES) last_seen;
	register<bit<48>>(BLOOM_FILTER_ENTRIES) last_malicous_classified;

	// durations
	register<bit<48>>(BLOOM_FILTER_ENTRIES) flow_duration;
	register<bit<48>>(BLOOM_FILTER_ENTRIES) active_min;
	register<bit<48>>(BLOOM_FILTER_ENTRIES) flow_iat_min;

	// flow identification
	register<ip4Addr_t>(BLOOM_FILTER_ENTRIES) init_src_addr;
	register<ip4Addr_t>(BLOOM_FILTER_ENTRIES) init_dst_addr;
	register<bit<1>>(BLOOM_FILTER_ENTRIES) known_flow;
	register<bit<1>>(BLOOM_FILTER_ENTRIES) malicious_flow;

	action drop() {
		mark_to_drop(standard_metadata);
	}

	action find_and_store_hash() {
		// getting the position in bloom_filter where the current flow_stats are stored
		hash(meta.flow_pos,
		     HashAlgorithm.crc16,
			 (bit<16>)0,
			 {hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr,
              hdr.tcp.srcPort,
              hdr.tcp.dstPort,
              hdr.ipv4.protocol},
			  (bit<16>)BLOOM_FILTER_ENTRIES);
	}

	action update_flow_stats() {
		// short name
		bit<48> igt = standard_metadata.ingress_global_timestamp;

		// by default should be 0 in bmv2, which means we haven't seen this flow before
		if (meta.known_flow == 0) {
			// set it as know flow
			meta.known_flow = 1;

			// flow starts right now
			meta.flow_start_timestamp = igt;
			meta.active_flow_start_timestamp = igt;

			// initial stuff
			meta.init_win_byte_forward = (bit<32>)hdr.tcp.window;
			meta.init_src_addr = hdr.ipv4.srcAddr;
			meta.init_dst_addr = hdr.ipv4.dstAddr;
		} else {
			if (igt - meta.last_seen < ACTIVE_FLOW_THRESHOLD) {
			} else {
				bit<48> current_active_flow_duration
					= meta.last_seen - meta.active_flow_start_timestamp;
				if (meta.active_min < current_active_flow_duration) {
					meta.active_min = current_active_flow_duration;
				}
				meta.active_flow_start_timestamp = igt;
			}
		}

		if (hdr.tcp.psh == 1) {
			meta.psh_flag_count = meta.psh_flag_count + 1;
		}

		if (hdr.tcp.syn == 1) {
			meta.syn_flag_count = meta.syn_flag_count + 1;
		}

		if (hdr.tcp.ack == 1) {
			meta.ack_flag_count = meta.ack_flag_count + 1;
		}

		bit<48> current_iat = igt - meta.last_seen;
		if (current_iat < meta.flow_iat_min) {
			meta.flow_iat_min = current_iat;
		}

		meta.total_packets = meta.total_packets + 1;

		if (meta.init_src_addr == hdr.ipv4.srcAddr) {
			meta.total_length_of_fwd_packets
				= meta.total_length_of_fwd_packets
				  + (bit<32>)hdr.ipv4.totalLen
				  - ((bit<32>)hdr.ipv4.ihl * 4)
				  - (bit<32>)hdr.tcp.dataOffset;
		}

		meta.last_seen = igt;
		meta.flow_duration = igt - meta.flow_start_timestamp;

		// TODO:
		// [X] - psh_flag_count
		// [X] - flow_duration
		// [X] - syn_flag_count
		// [X] - ack_flag_count
		// [X] - total_packets
		// [X] - total_length_of_fwd_packets
		// [X] - init_win_byte_forward
		// [X] - active_min
		// [X] - flow_iat_min
		// [-] - subflow_fwd_bytes => how to divide in p4?
		// [-] - avg_packer_size => how to divide in p4?
		// [-] - active_mean => how to divide in p4?
	}

	action check_feature(bit<16> node_id, bit<16> feature_index, bit<48> threshold) {
		bit<48> feature_value = 0;

		if (feature_index == 0) {
			feature_value = (bit<48>)meta.psh_flag_count;
		} else if (feature_index == 1) {
			feature_value = (bit<48>)meta.flow_duration;
		} else if (feature_index == 2) {
			feature_value = (bit<48>)meta.syn_flag_count;
		} else if (feature_index == 3) {
			feature_value = (bit<48>)meta.ack_flag_count;
		} else if (feature_index == 4) {
			feature_value = (bit<48>)meta.total_packets;
		} else if (feature_index == 5) {
			feature_value = (bit<48>)meta.total_length_of_fwd_packets;
		} else if (feature_index == 6) {
			feature_value = (bit<48>)meta.init_win_byte_forward;
		} else if (feature_index == 7) {
			feature_value = (bit<48>)meta.active_min;
		} else if (feature_index == 8) {
			feature_value = (bit<48>)meta.flow_iat_min;
		}
		// ASSUMPTION: feature_index is always valid

		if (feature_value < threshold) {
			meta.feature_less_than_threshold = 1;
		}

		meta.previous_feature = feature_index;
		meta.node_id = node_id;
	}

	action add_value(bit<16> value) {
		meta.total_value = meta.total_value + value;
		meta.stop_traversal = 1;
	}

	action sub_value(bit<16> value) {
		meta.total_value = meta.total_value - value;
		meta.stop_traversal = 1;
	}

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

	table tree0_level0 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree0_level1 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree0_level2 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree0_level3 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree0_level4 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree1_level0 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree1_level1 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree1_level2 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree1_level3 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree1_level4 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree2_level0 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree2_level1 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree2_level2 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree2_level3 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree2_level4 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree3_level0 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree3_level1 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree3_level2 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree3_level3 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree3_level4 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree4_level0 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree4_level1 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree4_level2 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree4_level3 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table tree4_level4 {
		key = {
			meta.node_id: exact;
			meta.previous_feature: exact;
			meta.feature_less_than_threshold: exact;
		}

		actions = {
			check_feature;
			add_value;
			sub_value;
			NoAction;
		}

		size = 100;
		default_action = NoAction();
	}

	table ipv4_exact {
		key = {
			meta.malicious_flow: exact;
		}

		actions = {
			ipv4_forward;
			drop;
		}

		size = 10;
		default_action = drop();
	}

	apply {
		if (hdr.ipv4.isValid() && hdr.ipv4.protocol == TYPE_TCP) {
			// find index of register
			find_and_store_hash();

			// get flow stats

			// flag counts
			psh_flag_count             .read(meta .psh_flag_count              , meta.flow_pos);
			syn_flag_count             .read(meta .syn_flag_count              , meta.flow_pos);
			ack_flag_count             .read(meta .ack_flag_count              , meta.flow_pos);
			total_packets              .read(meta .total_packets               , meta.flow_pos);

			// lengths
			total_length_of_packets    .read(meta .total_length_of_packets     , meta.flow_pos);
			total_length_of_fwd_packets.read(meta .total_length_of_fwd_packets , meta.flow_pos);
			init_win_byte_forward      .read(meta .init_win_byte_forward       , meta.flow_pos);

			// timestamps
			flow_start_timestamp       .read(meta .flow_start_timestamp        , meta.flow_pos);
			active_flow_start_timestamp.read(meta .active_flow_start_timestamp , meta.flow_pos);
			last_seen                  .read(meta .last_seen                   , meta.flow_pos);
			last_malicous_classified   .read(meta .last_malicous_classified    , meta.flow_pos);

			// durations
			flow_duration              .read(meta .flow_duration               , meta.flow_pos);
			active_min                 .read(meta .active_min                  , meta.flow_pos);
			flow_iat_min               .read(meta .flow_iat_min                , meta.flow_pos);

			// flow identification
			known_flow                 .read(meta .known_flow                  , meta.flow_pos);
			init_src_addr             .read(meta .init_src_addr              , meta.flow_pos);
			init_dst_addr             .read(meta .init_dst_addr              , meta.flow_pos);
			malicious_flow             .read(meta .malicious_flow              , meta.flow_pos);

			// update flow stats
			update_flow_stats();

			// set flow stats

			// flag counts
			psh_flag_count             .write(meta.flow_pos, meta .psh_flag_count             );
			syn_flag_count             .write(meta.flow_pos, meta .syn_flag_count             );
			ack_flag_count             .write(meta.flow_pos, meta .ack_flag_count             );
			total_packets              .write(meta.flow_pos, meta .total_packets              );

			// lenghts
			total_length_of_packets    .write(meta.flow_pos, meta .total_length_of_packets    );
			total_length_of_fwd_packets.write(meta.flow_pos, meta .total_length_of_fwd_packets);
			init_win_byte_forward      .write(meta.flow_pos, meta .init_win_byte_forward      );

			// timestamps
			flow_start_timestamp       .write(meta.flow_pos, meta .flow_start_timestamp       );
			last_seen                  .write(meta.flow_pos, meta .last_seen                  );
			active_flow_start_timestamp.write(meta.flow_pos, meta .active_flow_start_timestamp);

			// durartions
			flow_duration              .write(meta.flow_pos, meta .flow_duration              );
			active_min                 .write(meta.flow_pos, meta .active_min                 );
			flow_iat_min               .write(meta.flow_pos, meta .flow_iat_min               );
			// not updating last_malicous_classified

			// flow identification
			known_flow                 .write(meta.flow_pos, meta .known_flow                 );
			init_src_addr             .write(meta.flow_pos, meta .init_src_addr             );
			init_dst_addr             .write(meta.flow_pos, meta .init_dst_addr             );
			// not updating malicious_flow

			// reject if a) already classified as malicious and b) last time classified as
			// malicious was 10 mins back
			if (meta.malicious_flow == 1) {
				if (meta.last_malicous_classified + MALICIOUS_TIMEOUT
					< standard_metadata.ingress_global_timestamp) {
					drop();
					return;
				}

				// if we reach here means timeout done, retest for malicious_flow. note that we
				// have updated the stats
				meta.malicious_flow = 0;
			}

			meta.previous_feature = NO_FEATURE;
			meta.total_value = 0;
			meta.stop_traversal = 0;

			// tree 0
			tree0_level0.apply();
			if (meta.stop_traversal == 0) {
				tree0_level1.apply();
				if (meta.stop_traversal == 0) {
					tree0_level2.apply();
					if (meta.stop_traversal == 0) {
						tree0_level3.apply();
						if (meta.stop_traversal == 0) {
							tree0_level4.apply();
						}
					}
				}
			}

			meta.previous_feature = NO_FEATURE;
			meta.stop_traversal = 0;

			// tree 1
			tree1_level0.apply();
			if (meta.stop_traversal == 0) {
				tree1_level1.apply();
				if (meta.stop_traversal == 0) {
					tree1_level2.apply();
					if (meta.stop_traversal == 0) {
						tree1_level3.apply();
						if (meta.stop_traversal == 0) {
							tree1_level4.apply();
						}
					}
				}
			}

			meta.previous_feature = NO_FEATURE;
			meta.stop_traversal = 0;

			// tree 2
			tree2_level0.apply();
			if (meta.stop_traversal == 0) {
				tree2_level1.apply();
				if (meta.stop_traversal == 0) {
					tree2_level2.apply();
					if (meta.stop_traversal == 0) {
						tree2_level3.apply();
						if (meta.stop_traversal == 0) {
							tree2_level4.apply();
						}
					}
				}
			}

			meta.previous_feature = NO_FEATURE;
			meta.stop_traversal = 0;

			// tree 3
			tree3_level0.apply();
			if (meta.stop_traversal == 0) {
				tree3_level1.apply();
				if (meta.stop_traversal == 0) {
					tree3_level2.apply();
					if (meta.stop_traversal == 0) {
						tree3_level3.apply();
						if (meta.stop_traversal == 0) {
							tree3_level4.apply();
						}
					}
				}
			}

			meta.previous_feature = NO_FEATURE;
			meta.stop_traversal = 0;

			// tree 4
			tree4_level0.apply();
			if (meta.stop_traversal == 0) {
				tree4_level1.apply();
				if (meta.stop_traversal == 0) {
					tree4_level2.apply();
					if (meta.stop_traversal == 0) {
						tree4_level3.apply();
						if (meta.stop_traversal == 0) {
							tree4_level4.apply();
						}
					}
				}
			}

			if (meta.total_value < 500) {
				meta.malicious_flow = 0;
			} else {
				meta.malicious_flow = 1;
			}

			ipv4_exact.apply();
		}
	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

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

/*************************************************************************

***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
