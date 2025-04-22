import os
import json
import time
import logging
from collections import defaultdict
import hashlib
from scapy.all import sniff, IP
from scapy.layers.inet import TCP, UDP, ICMP
from datetime import datetime

# Set up logging
logging.basicConfig(filename='sniff_errors.log', level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s')

# Create a folder for saving packets
output_folder = "captured_packets"
os.makedirs(output_folder, exist_ok=True)

# Create filenames with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
packet_file = os.path.join(output_folder, f"packets_{timestamp}.json")
feature_file = os.path.join(output_folder, f"flows_{timestamp}.json")
mapping_file = os.path.join(output_folder, f"packet_flow_map_{timestamp}.json")

# Open files in append mode
packet_file_handle = open(packet_file, "a")
feature_file_handle = open(feature_file, "a")
mapping_file_handle = open(mapping_file, "a")

# Flow table and timeout
flow_table = defaultdict(list)
flow_start_times = {}
FLOW_TIMEOUT = 10  # 10 seconds for more packets per flow
last_cleanup = time.time()
last_packet_time = {}  # Track last packet time for idle calculation
packet_to_flow = []  # Store packet-to-flow mappings

def generate_flow_id(packet):
    """Generate a unique FlowID from 5-tuple."""
    try:
        if IP not in packet:
            return None
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        src_port = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0
        five_tuple = (src_ip, dst_ip, src_port, dst_port, proto_num)
        return hashlib.md5(str(five_tuple).encode()).hexdigest()[:8]
    except Exception as e:
        logging.error(f"Error generating FlowID: {e}")
        return None

def calculate_features(packets, flow_start_time):
    """Calculate features for a flow."""
    if not packets:
        return {}
    try:
        total_packets = len(packets)
        # Forward packet detection: assume client initiates (first packet is forward)
        fwd_packets = sum(1 for i, p in enumerate(packets) if i == 0 or (p["src_ip"] == packets[0]["src_ip"] and p["src_port"] == packets[0]["src_port"]))
        total_time = time.time() - flow_start_time if flow_start_time else 0.001  # Avoid division by zero
        
        # Use packet timestamps from scapy
        iat_list = [packets[i+1]["timestamp"] - packets[i]["timestamp"] for i in range(len(packets)-1)] if len(packets) > 1 else [0]
        fwd_iat_list = [packets[i+1]["timestamp"] - packets[i]["timestamp"] for i in range(len(packets)-1) if packets[i]["is_forward"] and packets[i+1]["is_forward"]] if len(packets) > 1 else [0]
        packet_lengths = [p["packet_length"] for p in packets]
        fwd_packet_lengths = [p["packet_length"] for p in packets if p["is_forward"]]
        first_packet = packets[0]["packet"]

        # Calculate idle periods (time since last packet in flow)
        idle_times = [packets[i]["timestamp"] - packets[i-1]["timestamp"] for i in range(1, len(packets)) if packets[i]["timestamp"] - packets[i-1]["timestamp"] > 1] if len(packets) > 1 else [0]

        return {
            "iat_mean": sum(iat_list) / len(iat_list) if iat_list else 0.0,
            "fwd_iat_mean": sum(fwd_iat_list) / len(fwd_iat_list) if fwd_iat_list else 0.0,
            "packet_length_mean": sum(packet_lengths) / total_packets if total_packets else 0.0,
            "fwd_packet_length_mean": sum(fwd_packet_lengths) / fwd_packets if fwd_packets else 0.0,
            "iat_std": (sum((x - (sum(iat_list)/len(iat_list) if iat_list else 0))**2 for x in iat_list) / len(iat_list))**0.5 if iat_list else 0.0,
            "fwd_packet_length_min": min(fwd_packet_lengths) if fwd_packet_lengths else 0.0,
            "iat_min": min(iat_list) if iat_list else 0.0,
            "init_fwd_win_bytes": first_packet[TCP].window if TCP in first_packet and packets[0]["is_forward"] else 0,
            "packet_length_variance": sum((x - (sum(packet_lengths)/total_packets if total_packets else 0))**2 for x in packet_lengths) / total_packets if total_packets else 0.0,
            "cwe_flag_count": sum(1 for p in packets if TCP in p["packet"] and p["packet"][TCP].flags & 0x40),
            "protocol": first_packet[IP].proto,
            "flow_packets_per_s": total_packets / total_time if total_time else 0.0,
            "fwd_packets_per_s": fwd_packets / total_time if total_time else 0.0,
            "fwd_psh_flags": sum(1 for p in packets if TCP in p["packet"] and p["packet"][TCP].flags & 0x08 and p["is_forward"]),
            "fwd_act_data_packets": sum(1 for p in packets if p["is_forward"] and p["packet_length"] > 0),
            "fwd_iat_std": (sum((x - (sum(fwd_iat_list)/len(fwd_iat_list) if fwd_iat_list else 0))**2 for x in fwd_iat_list) / len(fwd_iat_list))**0.5 if fwd_iat_list else 0.0,
            "avg_fwd_segment_size": sum(fwd_packet_lengths) / fwd_packets if fwd_packets else 0.0,
            "iat_max": max(iat_list) if iat_list else 0.0,
            "total_fwd_packets": fwd_packets,
            "subflow_fwd_packets": fwd_packets / total_packets if total_packets else 0.0,
            "fwd_iat_min": min(fwd_iat_list) if fwd_iat_list else 0.0,
            "urg_flag_count": sum(1 for p in packets if TCP in p["packet"] and p["packet"][TCP].flags & 0x20),
            "ack_flag_count": sum(1 for p in packets if TCP in p["packet"] and p["packet"][TCP].flags & 0x10),
            "rst_flag_count": sum(1 for p in packets if TCP in p["packet"] and p["packet"][TCP].flags & 0x04),
            "fwd_packet_length_std": (sum((x - (sum(fwd_packet_lengths)/fwd_packets if fwd_packets else 0))**2 for x in fwd_packet_lengths) / fwd_packets)**0.5 if fwd_packets else 0.0,
            "fwd_iat_max": max(fwd_iat_list) if fwd_iat_list else 0.0,
            "packet_length_min": min(packet_lengths) if packet_lengths else 0.0,
            "active_max": max([p["timestamp"] - flow_start_time for p in packets]) if packets else 0.0,
            "idle_mean": sum(idle_times) / len(idle_times) if idle_times else 0.0,
            "idle_min": min(idle_times) if idle_times else 0.0
        }
    except Exception as e:
        logging.error(f"Error calculating features: {e}")
        return {}

def packet_callback(packet):
    global last_cleanup
    try:
        if IP not in packet:
            return

        # Extract packet details
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        src_port = None
        dst_port = None
        protocol = str(proto_num)
        packet_length = len(packet)

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        # Generate FlowID
        flow_id = generate_flow_id(packet)
        
        # Store packet details with FlowID
        packet_data = {
            "timestamp": datetime.now().isoformat(),
            "protocol": protocol,
            "source_ip": src_ip,
            "source_port": src_port,
            "destination_ip": dst_ip,
            "destination_port": dst_port,
            "packet_length": packet_length,
            "flow_id": f"flow{flow_id}" if flow_id else "unknown"
        }

        # Write raw packet data
        packet_file_handle.write(json.dumps(packet_data) + "\n")
        packet_file_handle.flush()
        print(json.dumps(packet_data, indent=2))

        # Flow processing
        if flow_id:
            if flow_id not in flow_start_times:
                flow_start_times[flow_id] = time.time()
            pkt_timestamp = packet.time if hasattr(packet, 'time') else time.time()
            flow_table[flow_id].append({
                "packet": packet,
                "timestamp": pkt_timestamp,
                "packet_length": packet_length,
                "is_forward": False,  # Updated in feature calculation
                "src_ip": src_ip,
                "src_port": src_port
            })
            last_packet_time[flow_id] = pkt_timestamp

            # Store packet-to-flow mapping
            packet_to_flow.append({
                "packet_timestamp": packet_data["timestamp"],
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": protocol,
                "flow_id": f"flow{flow_id}"
            })
            mapping_file_handle.write(json.dumps({
                "packet_timestamp": packet_data["timestamp"],
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": protocol,
                "flow_id": f"flow{flow_id}"
            }) + "\n")
            mapping_file_handle.flush()

        # Clean up expired flows
        current_time = time.time()
        if current_time - last_cleanup > FLOW_TIMEOUT:
            for fid in list(flow_table.keys()):
                if current_time - flow_start_times[fid] > FLOW_TIMEOUT:
                    features = calculate_features(flow_table[fid], flow_start_times[fid])
                    if features:
                        output_json = {
                            "FlowID": f"flow{fid}",
                            "Flow_IAT_Mean": features["iat_mean"],
                            "Idle_Mean": features["idle_mean"],
                            "Fwd_IAT_Mean": features["fwd_iat_mean"],
                            "Packet_Length_Mean": features["packet_length_mean"],
                            "Fwd_Packet_Length_Mean": features["fwd_packet_length_mean"],
                            "Flow_IAT_Std": features["iat_std"],
                            "Fwd_Packet_Length_Min": features["fwd_packet_length_min"],
                            "Idle_Min": features["idle_min"],
                            "Flow_IAT_Min": features["iat_min"],
                            "Init_Fwd_Win_Bytes": features["init_fwd_win_bytes"],
                            "Packet_Length_Variance": features["packet_length_variance"],
                            "CWE_Flag_Count": features["cwe_flag_count"],
                            "Protocol": features["protocol"],
                            "Flow_Packets_per_s": features["flow_packets_per_s"],
                            "Fwd_Packets_per_s": features["fwd_packets_per_s"],
                            "Fwd_PSH_Flags": features["fwd_psh_flags"],
                            "Fwd_Act_Data_Packets": features["fwd_act_data_packets"],
                            "Fwd_IAT_Std": features["fwd_iat_std"],
                            "Avg_Fwd_Segment_Size": features["avg_fwd_segment_size"],
                            "Flow_IAT_Max": features["iat_max"],
                            "Total_Fwd_Packets": features["total_fwd_packets"],
                            "Subflow_Fwd_Packets": features["subflow_fwd_packets"],
                            "Fwd_IAT_Min": features["fwd_iat_min"],
                            "URG_Flag_Count": features["urg_flag_count"],
                            "ACK_Flag_Count": features["ack_flag_count"],
                            "RST_Flag_Count": features["rst_flag_count"],
                            "Fwd_Packet_Length_Std": features["fwd_packet_length_std"],
                            "Fwd_IAT_Max": features["fwd_iat_max"],
                            "Packet_Length_Min": features["packet_length_min"],
                            "Active_Max": features["active_max"]
                        }
                        feature_file_handle.write(json.dumps(output_json) + "\n")
                        feature_file_handle.flush()
                        print(json.dumps(output_json, indent=2))
                    del flow_table[fid]
                    del flow_start_times[fid]
            last_cleanup = current_time

    except Exception as e:
        logging.error(f"Error processing packet: {e}")
        print(f"Skipping problematic packet: {e}")

try:
    print(f"Saving raw packets to: {packet_file}")
    print(f"Saving flow features to: {feature_file}")
    print(f"Saving packet-to-flow mapping to: {mapping_file}")
    sniff(prn=packet_callback, store=0, timeout=3600)  # Run for 1 hour max
except Exception as e:
    print(f"Sniffing stopped due to error: {e}")
    logging.error(f"Sniffing error: {e}")
finally:
    # Write final packet-to-flow mappings
    for mapping in packet_to_flow:
        mapping_file_handle.write(json.dumps(mapping) + "\n")
    packet_file_handle.close()
    feature_file_handle.close()
    mapping_file_handle.close()
