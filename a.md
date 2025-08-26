So, we started of by understanding the PS. Defining what all is meant by the columns in the different CSVs. Acc. to the ps, the attack was a botnet attack, in which a victim gets infected, connects itself to the C2C server and goes on to act like a bot and infect other systems. 
Then, analysing the `dns_logs.csv` straight up led to some pretty suspicious domains with the suffix `silent-hydra.net`. 
We came across a paper linked [here](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final127.pdf)

### 1. Defining the Threat Model: DGA Botnets
The core assumption is a botnet using a Domain Generation Algorithm (DGA) to locate its C2 server. This method prioritizes stealth and resilience.
Compromised Host (Bot): A machine within our network that has been infected and is acting as a client to the botmaster.
External C2 Server: A remote server controlled by the attacker.
Communication Flow: A bot generates a large number of random domains and queries them one by one. The **single successful query** reveals the C2 server's IP address.

### 2. Key Features and Indicators of Compromise (IoCs)
The following features were identified as key indicators of malicious activity across the datasets.
DNS Logs (dns_logs.csv)
The DNS logs are the first place to look for signs of compromise.
DGA Domain Names: Query names that appear to be randomly generated (e.g., *silent-hydra.net). These are a primary indicator.
High NXDOMAIN Ratio: A single client_ip making a high volume of DNS queries that result in NXDOMAIN (domain not found) responses. This is a telltale sign of a bot trying to find its one active C2 domain among many fakes.
Uncommon Record Types: Queries for less-common records (e.g., TXT or CNAME) which can be used to tunnel data or commands.
So the domain that gets connected finally is the ip of the c2s server.

Once this c2c server ip is located we can backtrace the ips to the victims' client_ip.

#### Network Flows (network_flows.csv)
Network flows confirm the communication and provide behavioral context.
Beaconing: Consistent, low-volume connections from an internal source_ip to an external dest_ip at regular time intervals (e.g., every 5 minutes). This was observed in the victim ips obtained from the dns_logs file.
Unusual Ports: Outbound connections on ports not typically used for a host's role, such as 3389 (RDP) or 445 (SMB). Inbound connections on these ports from external IPs were also taken into consideration

#### Host Information (host_info.csv)
This file provides crucial context for prioritizing alerts. High amt of data on a webserver is normal compared to the same amount of bytes being sent/received in personal workstations.

### 3. The Correlation Process
The core of the investigation is connecting these findings.

#### Identify DGA Activity: Find the client_ips in the dns_logs.csv with a high NXDOMAIN ratio and a single successful query.
Pinpoint the C2 Server: Note the response_ips from the successful query. This is your C2 server candidate.
We found all the clients which were being attacked backtracked to the queries through network_flows.csv in which we checked, if the bytes have been sent and recived.
if so both, we declare that the client was succesfully attacked.

#### Confirm with Network Flows: Search network_flows.csv for the client_ip from step 1 acting as a source_ip and communicating with the C2 server IP from step 2. Look for beaconing behavior (regular time intervals) or data exfiltration(3389 or 445).

After that we can use host_info.csv to understand the role of the compromised host and assess the severity of the threat.
