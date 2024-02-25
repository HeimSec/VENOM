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

"""