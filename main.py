import sys, time
import scan
import DoS
from ui import Green, Grey, Red, BRIGHT_YELLOW
import ui

def shutdown():
    print(Green + "[!] Thank you for your use!" + Grey)
    sys.exit()

if __name__ == '__main__':
    ui.banner()

    while True:
        ui.choice()

        try:
            c = input(ui.header('Menu'))

            if c == '1':
                try:
                    interface_names = scan.get_interface_names()
                    while True:
                        interface_choice = int(input(ui.header("\nMenu")))
                        if scan.interface_name_check(interface_choice, interface_names):
                            break
                    target = input(ui.header("Enter the network address(e.x. 192.168.0.0/24): "))
                    scan.arp_scan(target, iface=interface_names[interface_choice - 1])
                except KeyboardInterrupt:
                    shutdown()

            elif c == '2':
                try:
                    target_ip = input(ui.header("Enter the target IP")).strip()
                    scan.portscan_menu()
                    scan_choice = input(ui.header("Menu")).strip()
                    scan_results = scan.portscan_main(target_ip, scan_choice)

                except KeyboardInterrupt:
                    shutdown()


            elif c == '3':
                try:
                    target_ip = input(ui.header("Enter the target IP").strip())
                    scan.banner_menu()
                    service_choice = input(ui.header("Menu"))
                    scan.banner_main(target_ip, service_choice)

                except KeyboardInterrupt:
                    shutdown()

            elif c in ['4', '5', '6', '7', '8', '9', '10', '11', '12', '13']:
                print(BRIGHT_YELLOW + "If you want to stop the DoS attack, press Ctrl+C")
                try:
                    attack_type = c
                    dst_IP = input(ui.header("Enter the target IP")).strip()

                    if (attack_type != '5'):
                        dst_port = int(input(ui.header("Enter the target port number")).strip())

                    run_threads = int(input(ui.header("Enter number of threads")).strip())

                    if attack_type in ['11', '12', '13']: # GET, HTTP Method, Hulk
                        src_IP = input(ui.header("Enter the Source IP")).strip()
                        url = input(ui.header("Enter the url")).strip()
                    if attack_type == '9': # Slowloris
                        src_IP = input(ui.header("Enter the Source IP")).strip()
                        socket_count = int(input(ui.header("Enter the socket count per thread")))

                    if attack_type not in ['4', '5', '6', '7', '8', '9', '10', '11', '12', '13']:
                        print("Invalid attack type. Choose valid number.")
                        sys.exit(1)

                    if c in ['4', '6', '7', '8', '10']:
                        DoS.DoS_num1(dst_IP, attack_type, run_threads, dst_port)
                    elif c in ['11', '12', '13']:
                        DoS.DoS_num2(src_IP, dst_IP, attack_type, run_threads, dst_port, url)
                    elif c == '5':
                        DoS.DoS_num3(dst_IP, attack_type, run_threads)
                    elif c == '9':
                        DoS.DoS_num4(src_IP, dst_IP, attack_type, run_threads, dst_port, socket_count)
                    elif KeyboardInterrupt:
                        continue

                except KeyboardInterrupt:
                    continue

                except ValueError as e:
                    print(f"Invalid input: {e}")
                    shutdown()


            elif c.lower() == 'h':
                ui.print_help()

            else:
                sys.stdout.write(Red + '[!] Out of range !' + Grey)
                time.sleep(1)
                continue

        except KeyboardInterrupt:
            print("")
            shutdown()