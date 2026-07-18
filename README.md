# Network Vulnerability Scanner

A Bash script that uses Nmap to scan a target for open ports and known vulnerabilities, generating a summary report of the findings. This project is the culmination of the Shell Scripting course.

## Features

* Accepts a target IP address or hostname from the command line.
* Validates IP address or hostname for formatting syntax
* Checks if validated target is reachable by Ping command
* Reprompts user if target syntax or Ping command Fails
* Performs an Nmap scan to detect services and versions.
* (Coming soon) Uses NSE scripts to check for specific vulnerabilities.
* (Coming soon) Generates a formatted report summarizing open ports and potential risks.
* Includes input validation and prerequisite checks.

## Prerequisites

To run this script, you will need the following installed:
* Bash (v4+)
* Nmap (v7.60+)

## Usage

1.  Clone the repository: `git clone git@github.com:YourUsername/my_scanner.git`
2.  Navigate to the directory: `cd my_scanner`
3.  Make the script executable: `chmod +x network_scannerv3.sh`
4.  Run the script with a target:
./network_scanner.sh 
5. follow Prompts for input needed to run the script

Example:
./network_scannerv3.sh
>Enter target IP or hostname
>10.0.0.0
>Invalid input (valid input syntax message)
>10.0.0.1
>checking if target is online
>target is offline, select a new target
>127.0.0.1
>checking if target is online
>target is online, running Nmap Scan now....
>(generates report)
 

## Ethical Considerations
This tool is for educational purposes only. Only run scans against hosts and networks for which you have explicit, written permission. Unauthorized network scanning is illegal.

Author
Jeremy Demoranville

