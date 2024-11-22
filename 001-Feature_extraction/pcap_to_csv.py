import pyshark
import pandas as pd

def pcap_to_csv(pcap_file, output_csv):
    # Đọc file PCAP
    cap = pyshark.FileCapture(pcap_file)

    # Lấy thông tin các gói tin
    packets = []
    for packet in cap:
        try:
            packets.append({
                "No.": packet.number,                      # Số thứ tự gói tin
                "Time": packet.sniff_time,                # Thời gian bắt gói tin
                "Src IP": packet.ip.src if hasattr(packet, 'ip') else None,  # IP nguồn
                "Src Port": packet.tcp.srcport if hasattr(packet, 'tcp') else (
                    packet.udp.srcport if hasattr(packet, 'udp') else None),  # Cổng nguồn
                "Dst IP": packet.ip.dst if hasattr(packet, 'ip') else None,  # IP đích
                "Dst Port": packet.tcp.dstport if hasattr(packet, 'tcp') else (
                    packet.udp.dstport if hasattr(packet, 'udp') else None),  # Cổng đích
                "Protocol": packet.highest_layer,         # Giao thức
                "Length": packet.length,                  # Độ dài gói tin
            })
        except AttributeError:
            continue

    # Ghi vào CSV
    df = pd.DataFrame(packets)
    df.to_csv(output_csv, index=False)
    print(f"Đã xuất dữ liệu ra {output_csv}")

# Sử dụng hàm
pcap_to_csv('2022_01_03_Active.pcap', '2022_01_03_Active.csv')
