from colorama import init, Style, Fore, Back
from prettytable import PrettyTable
import pyfiglet
import time

Green = '\033[92m'
Blue = '\033[94m'
Grey = '\033[0m'
Red = '\033[31m'
White = '\33[97m'
Yellow = '\33[93m'

init(autoreset=True)
RESET_COLORS = Style.RESET_ALL
BRIGHT_RED = Style.BRIGHT + Fore.RED
BRIGHT_WHITE = Style.BRIGHT + Fore.WHITE
BRIGHT_YELLOW = Style.BRIGHT + Fore.YELLOW
BACK_RED_BRIGHT_YELLOW = Back.RED + Style.BRIGHT + Fore.YELLOW


def banner():
    print(Green + pyfiglet.figlet_format('PyHTools'))
    time.sleep(1)


def print_help():
    print(Blue + "[*] Scan")
    table_scan = PrettyTable(["No", "Menu", "Description"])
    table_scan.add_row(["1", "IP", "Check active hosts IP"])
    table_scan.add_row(["2", "Port", "Scan well-known ports (1023)"])
    table_scan.add_row(["3", "Banner Grabbing", "Check service version information"])
    print(table_scan)

    print(Blue + "[*] DoS")
    table_dos = PrettyTable(["Performing a DoS attack on a target"])
    print(table_dos)

    print(Blue + "[*] Option")
    table_option = PrettyTable(["Command", "Description"])
    table_option.add_row(["h", "help"])
    table_option.add_row(["ctrl+c", "exit"])
    print(table_option)


def choice():
    print(BRIGHT_YELLOW + '+' + '-' * 44 + '+')
    print(BRIGHT_WHITE + '|       Please enter the number of menu      |')
    print(BRIGHT_YELLOW + '+' + '-' * 44 + '+')

    table = PrettyTable()

    table.field_names = ["Scan", "DoS"]

    table.add_row(["1. IP", "4. UDP Flooding"])
    table.add_row(["2. Port", "5. ICMP Flooding"])
    table.add_row(["3. Banner Grabbing", "6. SYN Flooding"])
    table.add_row(["", "7. LAND Attack"])
    table.add_row(["", "8. Teardrop Attack"])
    table.add_row(["", "9. Slowloris Attack"])
    table.add_row(["", "10. Rudy Attack"])
    table.add_row(["", "11. GET Flooding"])
    table.add_row(["", "12. HTTP Method Flooding"])
    table.add_row(["", "13. Hulk DoS"])

    table.align = "l"
    table.field_names = [White + table.field_names[0].center(17), table.field_names[1].center(23) + White]

    print(table)
    print(Blue + "h " + White + "> help\n" + RESET_COLORS)


def header(name):
    return '{}{}{}> {}'.format(Blue, name, White, Grey)


if __name__ == "__main__":
    banner()
    print_help()
    choice()