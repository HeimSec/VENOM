"""
CODENAME   :    VENOM.py
DESCRIPTION:    Simple tryout of a Port Scanner
DEVELOPER  :    Jan Gebser (@Brainhub24)
REPORSITORY:    https://github.com/HeimSec/VENOM


I want to try to build a basic port scanner that can scans a target for open ports within the range of 1 to 65535.
It should provide a minimalistic command-line interface for the user to enter the target network (IP or FQDN).
I´m testing multi-threading to provide a scanning animation during the port scanning process.

Example:
Enter the target: fritz.box

Scanning Target: 192.168.178.1
Scanning started at: [DATE] [TIMESTAMP]
--------------------------------------------------
Scanning... done!
Port 21 is [RESULT]


First working version including some issues that need to be resolve:
┌──(ironcore㉿LAB.ONE)-[~/Development/GitHub/VENOM]
└─$ python3 VENOM.py
--------------------------------------------------

Enter the target network (IP or domain)
or type 'Bye' to quit: fritz.box

--------------------------------------------------
PORT SCANNER
A project by: https://www.heimdall-security.net
--------------------------------------------------
Scanning Target: 192.168.178.1
Scanning started at: 2024-02-25 08:19:12.488290
--------------------------------------------------
Scanning... done!
Port 21 is open
Scanning... done!
Port 53 is open
Scanning... done!
Port 80 is open
Scanning... done!
Port 443 is open
Scanning... \^CTraceback (most recent call last):
  File "~/Development/GitHub/VENOM/VENOM.py", line 84, in <module>
Scanning... |    VENOM_TARGETS(target)
  File "~/Development/GitHub/VENOM/VENOM.py", line 59, in VENOM_TARGETS
    result = s.connect_ex((target, port))
KeyboardInterrupt
Scanning... |^CException ignored in: <module 'threading' from '/usr/lib/python3.10/threading.py'>
Traceback (most recent call last):
  File "/usr/lib/python3.10/threading.py", line 1567, in _shutdown
    lock.acquire()
KeyboardInterrupt:
"""
import sys
import time
from datetime import datetime
import socket
import argparse
import pyfiglet
import threading
import itertools

__VENOM__ = "__main__"
    
def VENOM_ANSI_BANNER():
    VENOM_CODENAME = pyfiglet.figlet_format("VENOM PORTSCAN", font="slant")
    VENOM_CONTENT_COLOR = "\033[92m" + VENOM_CODENAME + "\033[0m"
    print(VENOM_CONTENT_COLOR, end='')

def VENOM_SCAN_ANIMATION():
    """
    Function to display a scanning animation during the port scanning process.
    """
    chars = "/—\|"
    for char in itertools.cycle(chars):
        sys.stdout.write('\rScanning... ' + char)
        sys.stdout.flush()
        time.sleep(0.1)

def VENOM_TARGETS(target, VENOM_INFO_OUTPUT):
    """
    Function to scan open ports on a target and display the results.
    
    Param target: The target IP address or the Fully Qualified Domain Name [FQDN] to scan.
                   https://url.webservice.digital/FQDN
    """
    VENOM_ANSI_BANNER()

    print("\n" + "-" * 75)
    print("Unleash the Storm, Dominate the Ports!")
    print("A project by: https://www.heimdall-security.net")
    print("-" * 75)

    if not target and not VENOM_INFO_OUTPUT:
        print("\nUsage: VENOM.py [-h] [-info] target\n")
        print("Options:")
        print("  -h, --help  show this help message and exit")
        print("  -info       Display detailed information for open ports.")
        sys.exit()

    if VENOM_INFO_OUTPUT:
        VENOM_DISPLAY_ALL_PORTS_INFO()
    else:
        print(f"Scanning Target: {target}")
        print(f"Scanning started at: {str(datetime.now())}")
        print("-" * 75)

        try:
            VENOM_SCAN_PROCESS = threading.Thread(target=VENOM_SCAN_ANIMATION)
            VENOM_SCAN_PROCESS.start()

            VENOM_UNLEASHED_PORTS = []
            for port in range(1, 65536):
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        sys.stdout.write('\rScanning... done!')
                        sys.stdout.flush()
                        print(f"\nPort {port} is open")

                        VENOM_UNLEASHED_PORTS.append(port)

            VENOM_SCAN_PROCESS.join()

            if VENOM_INFO_OUTPUT:
                VENOM_DISPLAY_ALL_PORTS_INFO(VENOM_UNLEASHED_PORTS)

        except socket.gaierror:
            print("\nHostname Could Not Be Resolved !!!")
        except socket.error:
            print("\nServer not responding !!!")

def VENOM_DISPLAY_ALL_PORTS_INFO(VENOM_UNLEASHED_PORTS=None):
    VENOM_MOST_WANTED = {
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

    if VENOM_UNLEASHED_PORTS is not None:
        for VENOM_PORT_LISTENER in VENOM_UNLEASHED_VENOM_PORT_LISTENERS:
            if VENOM_PORT_LISTENER in VENOM_MOST_WANTED:
                service = VENOM_MOST_WANTED[VENOM_PORT_LISTENER].split(' - ')[0]
                description = VENOM_MOST_WANTED[VENOM_PORT_LISTENER].split(' - ')[1]
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
