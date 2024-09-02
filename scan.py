from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from scapy.layers.l2 import ARP, Ether, srp
from prettytable import PrettyTable
import datetime
from ui import Green, Blue, Grey, Red, White, Yellow, BRIGHT_YELLOW
from port import port_services
import requests
import telnetlib
import psutil
import threading

src_port = random.randint(1024, 65535)
print_lock = Lock()

def get_interface_names():
    interfaces = psutil.net_if_addrs()
    interface_names = []
    for interface_name, _ in interfaces.items():
        interface_names.append(interface_name)

    print(Blue + '\n[*] ' + White + "Choose the number of network interface")

    table = PrettyTable()
    table.field_names = ["No", "Interface name"]
    table.align = "c"
    table.field_names = [White + table.field_names[0].center(10),
                         table.field_names[1].center(10) + White]

    for interface_num, name in enumerate(interface_names, start=1):
        table.add_row([interface_num, name])

    print(table)
    return interface_names

def interface_name_check(interface_choice, interface_names):
    name_length = len(interface_names)

    if interface_choice in range(1, name_length + 1):
        iface = interface_names[interface_choice - 1]
        return iface
    else:
        sys.stdout.write(Red + '[!] Out of range !' + Grey)
        return None

class ARP_Thread(threading.Thread):
    def __init__(self, packet, iface, results, lock):
        threading.Thread.__init__(self)
        self.packet = packet
        self.iface = iface
        self.result = results
        self.lock = lock
        self.clients = []

    def run(self):
        result = srp(self.packet, iface=self.iface, timeout=4, verbose=0)[0]
        self.clients = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]

        with self.lock:
            self.result.extend(self.clients)

def arp_scan(target, iface=None, run_threads = 30):
    arp = ARP(pdst=target)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    print(Green + "Scanning your network, hang on...\n")

    results = []
    lock = threading.Lock()
    threads = []


    for _ in range(run_threads):
        arp_request_thread = ARP_Thread(packet, iface, results,
                                        lock)
        threads.append(arp_request_thread)
        arp_request_thread.start()

    # Wait for threads to complete
    for thread in threads:
        thread.join()

    unique_clients = {client['ip']: client for client in results}.values()

    if not unique_clients:
        print(Red + "No devices found on the network.")
        return []

    print(Green + "OnLineIp: " + White + '\n')
    for index, client in enumerate(unique_clients):
        print("    [" + Yellow + f"{index}" + White + "]  "
              + White + f"{client['ip']:16}   {client['mac']}")
    return unique_clients

def get_ftp(target_ip, port=21):
    try:
        # TCP 3-way handshake
        syn = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")
        syn_ack = sr1(syn, timeout=3, verbose=0)
        if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
            # Send ACK
            ack = IP(dst=target_ip) / TCP(sport=syn_ack[TCP].dport,
                                          dport=port,
                                          flags="A",
                                          seq=syn_ack[TCP].ack,
                                          ack=syn_ack[TCP].seq + 1)
            packet = sr1(ack, timeout=5, verbose=0)

            if packet and packet.haslayer(Raw):
                banner = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                return banner
            else:
                return "No banner received"
        else:
            return "Failed to establish connection"
    except Exception as e:
        return f"Error: {str(e)}"

def get_ssh(target_ip, port=22):
    try:
        # TCP 3-way handshake
        syn = IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")
        syn_ack = sr1(syn, timeout=3, verbose=0)
        if syn_ack and syn_ack.haslayer(TCP) and syn_ack[TCP].flags == 0x12:
            # Send ACK
            ack = IP(dst=target_ip) / TCP(sport=syn_ack[TCP].dport,
                                          dport=port,
                                          flags="A",
                                          seq=syn_ack[TCP].ack,
                                          ack=syn_ack[TCP].seq + 1)
            packet = sr1(ack, timeout=5, verbose=0)

            if packet and packet.haslayer(Raw):
                banner = packet[Raw].load.decode('utf-8', errors='ignore').strip()
                return banner
            else:
                return "No banner received"
        else:
            return "Failed to establish connection"
    except Exception as e:
        return f"Error: {str(e)}"

def get_telnet(target_ip, port=23, timeout=5):
    try:
        tn = telnetlib.Telnet(target_ip, port, timeout)
        banner = tn.read_until(b"\n", timeout).decode('utf-8', errors='ignore').strip()
        tn.close()
        return banner if banner else "No banner received"
    except Exception as e:
        return f"Error: {str(e)}"

def get_http_request(target_ip, port=80):
    try:
        url = f"http://{target_ip}:{port}"
        response = requests.get(url, timeout=5)
        server_header = response.headers.get("Server", "No Server header found")
        return server_header if server_header else "No banner received"
    except requests.exceptions.RequestException as e:
        return f"An error occurred: {str(e)}"


def ack(target_ip, dst_port): # 6. ACK Scan
    try:
        ack_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="A"), timeout=2, verbose=0)
        if ack_resp is None:
            ack_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="A"), timeout=2, verbose=0)
            if ack_resp is None:
                return "Filtered"
            elif ack_resp.getlayer(TCP).flags == 0x4:  # RST
                return "Unfiltered"
            elif (ack_resp.haslayer(ICMP)):
                if (int(ack_resp.getlayer(ICMP).type) == 3 and int(ack_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return "Filtered"

        elif ack_resp.haslayer(TCP):
            if ack_resp.getlayer(TCP).flags == 0x4:  # RST
                return "Unfiltered"
        elif (ack_resp.haslayer(ICMP)):
            if (int(ack_resp.getlayer(ICMP).type) == 3 and int(ack_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                return "Filtered"

    except Exception as e:
        return f"Error: {str(e)}"

def tcp_connect(target_ip, dst_port): # 1. TCP Connect Scan
    try:
        # TCP SYN
        tcp_connect_resp = sr1(IP(dst=target_ip) /
                               TCP(sport=src_port, dport=dst_port, flags="S"), timeout=2, verbose=0)

        if tcp_connect_resp is None:
            return "Closed"
        elif tcp_connect_resp.haslayer(TCP):
            if tcp_connect_resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                ack_pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port,
                                                    seq= tcp_connect_resp[TCP].ack,
                                                    ack= tcp_connect_resp[TCP].seq + 1, flags='A')
                send(ack_pkt, verbose=0)
                rst_ack_pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port,
                                                      seq=tcp_connect_resp[TCP].ack,
                                                      ack=tcp_connect_resp[TCP].seq + 1, flags='RA')
                send(rst_ack_pkt, verbose=0)
                return "Open"
            elif tcp_connect_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                return "Closed"
    except Exception as e:
        return f"Error: {str(e)}"

def tcp_halfopen(target_ip, dst_port): # 2. TCP Half-Open Scan
    try:
        # TCP SYN
        tcp_halfopen_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=2, verbose=0)

        if tcp_halfopen_resp is None:
            tcp_halfopen_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="S"),timeout=2,verbose=0)
            if tcp_halfopen_resp is None:
                return "Filtered"
            elif tcp_halfopen_resp.haslayer(TCP):
                if tcp_halfopen_resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                    send(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="R"), verbose=0)  # RST
                    return "Open"
                elif tcp_halfopen_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return "Closed"
            elif (tcp_halfopen_resp.haslayer(ICMP)):  # 3 : Destination unreachable
                if (int(tcp_halfopen_resp.getlayer(ICMP).type) == 3 and int(tcp_halfopen_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return "Filtered"

        elif tcp_halfopen_resp.haslayer(TCP):
            if tcp_halfopen_resp.getlayer(TCP).flags == 0x12:  # SYN-ACK
                send(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="R"),verbose=0) # RST
                return "Open"
            elif tcp_halfopen_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                return "Closed"

        elif (tcp_halfopen_resp.haslayer(ICMP)): #3 : Destination unreachable
            if (int(tcp_halfopen_resp.getlayer(ICMP).type) == 3 and int(tcp_halfopen_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                return "Filtered"

    except Exception as e:
        return f"Error: {str(e)}"

def xmas(target_ip, dst_port): # 3. X-MAS Scan
    try:
        # PSH, FIN, URG
        xmas_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="FPU"), timeout=2, verbose=0)
        if xmas_resp is None:
            xmas_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="FPU"), timeout=2, verbose=0)
            if xmas_resp is None:
                return "Open|Filtered"
            elif xmas_resp.haslayer(TCP):
                if xmas_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return "Closed"
            elif (xmas_resp.haslayer(ICMP)):
                if (int(xmas_resp.getlayer(ICMP).type) == 3 and int(xmas_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return "Filtered"

        elif xmas_resp.haslayer(TCP):
            if xmas_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                return "Closed"
        elif (xmas_resp.haslayer(ICMP)):
            if (int(xmas_resp.getlayer(ICMP).type) == 3 and int(xmas_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                return "Filtered"
    except Exception as e:
        return f"Error: {str(e)}"

def fin(target_ip, dst_port): # 4. FIN Scan
    try:
        # FIN
        fin_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="F"), timeout=2, verbose=0)

        if fin_resp is None:
            fin_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="F"), timeout=2, verbose=0)
            if fin_resp is None:
                return "Open|Filtered"
            elif fin_resp.haslayer(TCP):
                if fin_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return "Closed"
            elif (fin_resp.haslayer(ICMP)):
                if (int(fin_resp.getlayer(ICMP).type) == 3 and int(fin_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return "Filtered"

        elif fin_resp.haslayer(TCP):
            if fin_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                return "Closed"
        elif (fin_resp.haslayer(ICMP)):
            if (int(fin_resp.getlayer(ICMP).type) == 3 and int(fin_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                return "Filtered"
    except Exception as e:
        return f"Error: {str(e)}"

def null(target_ip, dst_port): # 5. Null Scan
    try:
        null_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags=""), timeout=2, verbose=0)
        if null_resp is None:
            null_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags=""), timeout=2, verbose=0)
            if null_resp is None:
                return "Open|Filtered"
            elif null_resp.haslayer(TCP):
                if null_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                    return "Closed"
            elif (null_resp.haslayer(ICMP)):
                if (int(null_resp.getlayer(ICMP).type) == 3 and int(null_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                    return "Filtered"
        elif null_resp.haslayer(TCP):
            if null_resp.getlayer(TCP).flags == 0x14:  # RST-ACK
                return "Closed"
        elif (null_resp.haslayer(ICMP)):
            if (int(null_resp.getlayer(ICMP).type) == 3 and int(null_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
                return "Filtered"
        return "Open|Filtered"
    except Exception as e:
        return f"Error: {str(e)}"

def tcp_window(target_ip, dst_port): #7. Window Scan
    try:
        tcp_window_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="A"), timeout=2, verbose=0)

        if tcp_window_resp is None:
            tcp_window_resp = sr1(IP(dst=target_ip) / TCP(sport=src_port, dport=dst_port, flags="A"), timeout=2,verbose=0)
            if tcp_window_resp is None:
                return "Filtered"
            elif tcp_window_resp.haslayer(TCP):
                if (tcp_window_resp.getlayer(TCP).window == 0) and (tcp_window_resp.getlayer(TCP).flags == 0x4):
                    return "Closed"
                elif (tcp_window_resp.getlayer(TCP).window > 0) and (tcp_window_resp.getlayer(TCP).flags == 0x4):
                    return "Open"
        elif tcp_window_resp.haslayer(TCP):
            if (tcp_window_resp.getlayer(TCP).window == 0) and (tcp_window_resp.getlayer(TCP).flags == 0x4):
                return "Closed"
            elif (tcp_window_resp.getlayer(TCP).window > 0) and (tcp_window_resp.getlayer(TCP).flags == 0x4) :
                return "Open"

    except Exception as e:
        return f"Error: {str(e)}"


def udp_scan(target_ip, dst_port): #8. UDP Scan
    try:
        udp_scan_resp = sr1(IP(dst=target_ip) / UDP(dport=dst_port), timeout=5, verbose=0)
        if udp_scan_resp is None:
            udp_scan_resp = sr1(IP(dst=target_ip) / UDP(dport=dst_port), timeout=5, verbose=0)
            if udp_scan_resp is None:
                return "Open|Filtered"
            elif udp_scan_resp.haslayer(UDP):
                return "Open"
            elif udp_scan_resp.haslayer(ICMP):
                if (int(udp_scan_resp.getlayer(ICMP).type) == 3) and (int(udp_scan_resp.getlayer(ICMP).code) == 3):
                    return "Closed"
                elif (int(udp_scan_resp.getlayer(ICMP).type) == 3) and (int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
                    return "Filtered"

        elif udp_scan_resp.haslayer(UDP):
            return "Open"
        elif udp_scan_resp.haslayer(ICMP):
            if (int(udp_scan_resp.getlayer(ICMP).type) == 3) and (int(udp_scan_resp.getlayer(ICMP).code) == 3):
                return "Closed"
            elif (int(udp_scan_resp.getlayer(ICMP).type) == 3) and (int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
                return "Filtered"
    except Exception as e:
        return f"Error: {str(e)}"

def portscan_menu():
    print(BRIGHT_YELLOW + "\n[*] " + White + "Please enter the number")
    table = PrettyTable()
    table.field_names = ["No", "Scan type"]
    table.align = "c"
    table.field_names = [White + table.field_names[0].center(10), table.field_names[1].center(10) + White]
    table.add_row(["1", "TCP Connect Scan"])
    table.add_row(["2", "TCP Half-Open Scan"])
    table.add_row(["3", "X-MAS Scan"])
    table.add_row(["4", "FIN Scan"])
    table.add_row(["5", "Null Scan"])
    table.add_row(["6", "Ack Scan"])
    table.add_row(["7", "Window Scan"])
    table.add_row(["8", "UDP Scan"])
    print(table)

def scan_port(target_ip, port, scan_choice, scan_results):
    if scan_choice == '1':
        port_state = tcp_connect(target_ip, port)
    elif scan_choice == '2':
        port_state = tcp_halfopen(target_ip, port)
    elif scan_choice == '3':
        port_state = xmas(target_ip, port)
    elif scan_choice == '4':
        port_state = fin(target_ip, port)
    elif scan_choice == '5':
        port_state = null(target_ip, port)
    elif scan_choice == '6':
        port_state = ack(target_ip, port)
    elif scan_choice == '7':
        port_state = tcp_window(target_ip, port)
    elif scan_choice == '8':
        port_state = udp_scan(target_ip, port)
    else:
        sys.stdout.write(Red + '[!] Out of range !' + Grey)
        return

    with print_lock:
        scan_results[port_state].append((port, port_services[port]))

def portscan_main(target_ip, scan_choice):
    start_time = datetime.datetime.now()
    time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    print(Green + f"\nStarting Scan at {time}...")

    scan_results = {
        "Open": [],
        "Open|Filtered": [],
        "Filtered": [],
        "Unfiltered": [],
        "Closed": [],
    }

    threads = []

    for port, service in port_services.items():
        t = Thread(target=scan_port, args=(target_ip, port, scan_choice, scan_results))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    for state in ["Open", "Filtered", "Closed", "Open|Filtered", "Unfiltered"]:
        if scan_results[state]:
            print(Blue + '\n[*] ' + White + f"{state}")
            table = PrettyTable()
            table.field_names = ["Port", "Service"]
            table.align = "c"
            table.field_names = [White + table.field_names[0].center(10), table.field_names[1].center(10) + White]

            unknown_services = []
            for port, service in sorted(scan_results[state], key=lambda x: x[0]):
                if service != '-':
                    table.add_row([port, service])
                else:
                    unknown_services.append(port)

            if table.rows:
                print(table)

            if unknown_services:
                print(Red + f"Unknown Ports : {len(unknown_services)} {state}")

    end_time = datetime.datetime.now()
    scanning_time= end_time - start_time
    print(Green + f"\nScan completed in {round(scanning_time.total_seconds(), 0)} seconds.")
    return scan_results


def banner_menu():
    print(BRIGHT_YELLOW + '\n[*] ' + White + "Please port scan first")
    table = PrettyTable()
    table.field_names = ["No", "Port", "Service"]
    table.align = "c"
    table.field_names = [White + "No".center(10), "Port".center(10), "Service".center(15) + White]
    table.add_row(["1", "21", "FTP"])
    table.add_row(["2", "22", "SSH"])
    table.add_row(["3", "23", "Telnet"])
    table.add_row(["4", "80", "HTTP"])
    print(table)
def banner_main(target_ip, service_choice):
    conf.verb = 0
    if service_choice == '1':
        banner = get_ftp(target_ip)
        print(Red + f"FTP Banner > " + White + f"{banner}")
    elif service_choice == '2':
        banner = get_ssh(target_ip)
        print(Red + f"SSH Banner > " + White + f"{banner}")
    elif service_choice == '3':
        banner = get_telnet(target_ip)
        print(Red + f"Telnet Banner > " + White + f"{banner}")
    elif service_choice == '4':
        banner = get_http_request(target_ip)
        print(Red + f"HTTP Banner > " + White + f"{banner}")
    else:
        print("Invalid choice. Please enter a number between 1 and 4.")