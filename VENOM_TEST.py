import socket
import threading
import time
from datetime import datetime
import itertools
import sys
import argparse
import pyfiglet  # Added for ASCII banner

__VENOM__ = "__main__"

def display_venom_banner():
    banner = pyfiglet.figlet_format("VENOM", font="slant")
    print(banner, end='')

def VENOM_SCAN_ANIMATION():
    chars = "/—\|"
    for char in itertools.cycle(chars):
        sys.stdout.write('\rScanning... ' + char)
        sys.stdout.flush()
        time.sleep(0.1)

def VENOM_TARGETS(target, show_info):
    display_venom_banner()  # Display VENOM ASCII banner

    print("\n" + "-" * 50)
    print("PORT SCANNER")
    print("A project by: https://www.heimdall-security.net")
    print("-" * 50)

    if not target and not show_info:
        print("\nVENOM Port Scanner\nUsage: VENOM.py [-h] [-info] target\n")
        print("Options:")
        print("  -h, --help  show this help message and exit")
        print("  -info       Display detailed information for open ports.")
        sys.exit()

    if show_info:
        VENOM_DISPLAY_ALL_PORTS_INFO()
    else:
        print(f"Scanning Target: {target}")
        print(f"Scanning started at: {str(datetime.now())}")
        print("-" * 50)

        try:
            VENOM_SCAN_PROCESS = threading.Thread(target=VENOM_SCAN_ANIMATION)
            VENOM_SCAN_PROCESS.start()

            open_ports = []
            for port in range(1, 65536):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        sys.stdout.write('\rScanning... done!')
                        sys.stdout.flush()
                        print(f"\nPort {port} is open")

                        open_ports.append(port)

            VENOM_SCAN_PROCESS.join()

            if show_info:
                VENOM_DISPLAY_ALL_PORTS_INFO(open_ports)

        except socket.gaierror:
            print("\nHostname Could Not Be Resolved !!!")
        except socket.error:
            print("\nServer not responding !!!")

def VENOM_DISPLAY_ALL_PORTS_INFO(open_ports=None):
    well_known_ports_info = {
        21: "FTP - File Transfer Protocol. Used for transferring files between a server and a client.",
        22: "SSH - Secure Shell. Provides a secure channel over an unsecured network in a client-server architecture.",
        23: "Telnet. A network protocol used on the Internet or local area networks to provide a bidirectional interactive text-oriented communication facility.",
        25: "SMTP - Simple Mail Transfer Protocol. Used to send emails between servers.",
        53: "DNS - Domain Name System. Resolves domain names to IP addresses.",
        80: "HTTP - Hypertext Transfer Protocol. Used for transmitting hypertext over the Internet.",
        110: "POP3 - Post Office Protocol version 3. Retrieves emails from a mail server.",
        443: "HTTPS - Hypertext Transfer Protocol Secure. A combination of HTTP and a cryptographic protocol.",
    }

    print("\n" + "-" * 50)
    print("Port Information Table")
    print("-" * 50)
    print("{:<10} {:<30} {:<}".format("Port", "Service", "Description"))
    print("-" * 50)

    if open_ports is not None:
        for port in open_ports:
            if port in well_known_ports_info:
                service = well_known_ports_info[port].split(' - ')[0]
                description = well_known_ports_info[port].split(' - ')[1]
                print("{:<10} {:<30} {:<}".format(port, service, description))
            else:
                print(f"{port}       {'Unknown'}                     {'Unknown'}")

if __VENOM__ == "__main__":
    parser = argparse.ArgumentParser(description="VENOM Port Scanner")
    parser.add_argument("target", nargs="?", default=None, help="The target IP address or FQDN to scan.")
    parser.add_argument("-info", action="store_true", help="Display detailed information for open ports.")
    args = parser.parse_args()

    try:
        VENOM_TARGETS(args.target, args.info)

    except Exception as e:
        print(f"\nAn error occurred: {e}")
