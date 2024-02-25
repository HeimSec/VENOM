"""
Simple tryout of a Port Scanner

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
import socket
import threading
import time
from datetime import datetime
import itertools
import sys

__VENOM__ = "__main__"

def multi_threading_scan_animation():
    """
    Function to display a scanning animation during the port scanning process.
    """
    chars = "/—\|"
    for char in itertools.cycle(chars):
        sys.stdout.write('\rScanning... ' + char)
        sys.stdout.flush()
        time.sleep(0.1)

def VENOM_TARGETS(target):
    """
    Function to scan open ports on a target and display the results.
    
    :param target: The target IP address or the Fully Qualified Domain Name [FQDN] to scan.
                   https://url.webservice.digital/FQDN
    """
    print("\n" + "-" * 50)
    print("PORT SCANNER")
    print("A project by: https://www.heimdall-security.net")
    print("-" * 50)

    print(f"Scanning Target: {target}")
    print(f"Scanning started at: {str(datetime.now())}")
    print("-" * 50)

    try:
        animate_thread = threading.Thread(target=multi_threading_scan_animation)
        animate_thread.start()

        for port in range(1, 65536):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    sys.stdout.write('\rScanning... done!')
                    sys.stdout.flush()
                    print(f"\nPort {port} is open")

        animate_thread.join()

    except socket.gaierror:
        print("\nHostname Could Not Be Resolved !!!")
    except socket.error:
        print("\nServer not responding !!!")

if __VENOM__ == "__main__":
    print("-" * 50)

    while True:
        try:
            user_input = input("\nEnter the target: ")

            if user_input.lower() == "bye":
                print("Exiting the program. Goodbye!")
                break

            target = socket.gethostbyname(user_input)
            VENOM_TARGETS(target)

        except Exception as e:
            print(f"\nAn error occurred: {e}")
