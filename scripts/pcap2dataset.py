from scapy.all import rdpcap, TCP, UDP , IP

def pcap_to_dataset(pcap_file):
    # Read the PCAP file
    packets = rdpcap(pcap_file)
    
    # Create an empty list to store the data set
    data_set = []
    
    # Iterate through each packet in the PCAP file
    for packet in packets:
        # Extract the necessary information from the packet
        timestamp = packet.time
        source = packet[IP].src
        destination = packet[IP].dst
        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"
        length = len(packet)
        
        # Add the packet information to the data set
        data_set.append({
            "timestamp": timestamp,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "length": length
        })
    
    return data_set

# Test the function
data_set = pcap_to_dataset("example.pcap")
print(data_set)