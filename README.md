# host_discovery
Simple utility to scan network and detect operating system and device fingerprints

__________________________________________________________________________________________
>>> Installation <<<
__________________________________________________________________________________________
Ubuntu installation:
cat install_requirements_ubuntu.txt | xargs sudo apt-get install -y 
./install.sh

__________________________________________________________________________________________
Mac installation:
cat install_requirements_mac.txt | xargs brew install 
./instal.sh

__________________________________________________________________________________________
>>> Usage Examples <<<
__________________________________________________________________________________________
Auto-detect subnet and scan default nmap ports:
python3 main.py

Limit ports scanned to top 10 relevant ports (Increases speed):
python3 main.py -t 10

Include UDP ports (Makes scan very slow):
python3 main.py -t 10 -sU

Include UDP ports, reduce accuracy but keep performance:
python3 main.py -t 10 -sU --args "--min-parallelism 10 --max-retries 2"

Scan specific subset of ports (TCP 80,443 , UDP 53,137):
python3 main.py -p T:80,443,U:53,137 

Note that some map arguments are set by default:
-sS 
-sV --version-intensity 2 
-A 
-T4 
--script=banner,dns-service-discovery,ssl-cert 
--max-os-tries 2

Additional nmap flags may be set by --args:
python3 main.py --args="-Pn"
__________________________________________________________________________________________
>>> Usage and Parameters <<< 
__________________________________________________________________________________________
usage: main.py [-h] [-i INTERFACE] [-a ARGS] [-sU] [-p PORTS | -t TOP_PORTS] [target_spec]

If no arguments are passed, detects the subnet automatically,and uses default nmap ports.

positional arguments:
  target_spec           Can pass hostnames, IP addresses, networks, etc.
                        Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Specify interface to run tool on. If omitted, runs on default interface.
  -a ARGS, --args ARGS  Additional arguments for nmap. See nmap -h.
  -sU                   Scan UDP. Makes execution slow, low amount of ports recommended.
                        Consider using with:
                        	--args "--min-parallelism 10 --max-retries 2"
  -p PORTS, --ports PORTS
                        Only scan specified ports. Mutually exclusive with --top_ports.
                        Ex: -p 22; -p 1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  -t TOP_PORTS, --top_ports TOP_PORTS
                        Scan top <number> most common ports. Mutually exclusive with --ports.
