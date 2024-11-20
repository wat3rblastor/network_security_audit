import http.client
import json
import maxminddb
import os
import time
import re
import socket
import subprocess
import sys
from math import inf

# 
# Network Scanners
# 

# Return UNIX Epoch seconds
def scan_time():
    return time.time()

# Make sure that you are not returning the DNS server address
# Modify to include DNS list
def ipv4_addresses(domain):
    result = subprocess.check_output(["nslookup", domain], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    ip_addresses = re.findall(r'Address: ([0-9.]+)', result)
    return ip_addresses

def ipv6_addresses(domain):
    result = subprocess.check_output(["nslookup", "-type=AAAA", domain], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    ip_addresses = re.findall(r'AAAA address ([a-fA-F0-9:]+)', result)
    return ip_addresses

def http_server(domain):
    try:
        connection = http.client.HTTPSConnection(domain, 443, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        headers = response.getheaders()
        header_dict = dict(headers)
        server_name = header_dict.get("Server", None)
        return server_name
    except Exception as e:
        return None

# Tests if website listens for unencrypted HTTP requests on port 80
def insecure_http(domain):
    try:
        with socket.create_connection((domain, 80), timeout = 5) as sock:
            return True
    except (socket.timeout, socket.error):
        return False
    
def redirect_to_https(domain):
    try:
        connection = http.client.HTTPSConnection(domain, 443, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        status_code = response.status
        headers = response.getheaders()
        header_dict = dict(headers)
        if status_code in range(300, 310):
            location = header_dict.get("Location", None)
            if location is not None:
                return True
            else:
                return False
        else:
            return False
    except Exception as e:
        return None
    
def hsts(domain):
    try:
        connection = http.client.HTTPSConnection(domain, 443, timeout=5)
        connection.request("GET", "/")
        response = connection.getresponse()
        headers = response.getheaders()
        header_dict = dict(headers)
        hsts_header = header_dict.get("Strict-Transport-Security", None)
        if hsts_header:
            return True
        else:
            return False
    except Exception as e:
        # Check for this case
        return False
    
def tls_versions(domain):
    versions_of_tls = ["-tls1_3", "-tls1_2", "-tls1_1", "-tls1"]
    response = []

    for version in versions_of_tls:
        try:
            result = subprocess.check_output(
                ["openssl", "s_client", version, "-connect", domain+":443"],
                timeout=2,
                stderr=subprocess.STDOUT,
                input=b''
            ).decode("utf-8")
            if "Server certificate" in result:
                if version == "-tls1_3":
                    value = "TLSv1.3"
                elif version == "-tls1_2":
                    value = "TLSv1.2"
                elif version == "-tls1_1":
                    value = "TLSv1.1"
                elif version == "-tls1":
                    value = "TLSv1.0"
                else:
                    raise Exception("TLS Version is not one of the predetermined values.")
                response.append(value)
        except Exception as e:
            # print(f"{domain} does not support {version}: {e}")
            pass

    return response

def root_ca(domain):
    try:
        result = subprocess.check_output(
            ["openssl", "s_client", "-connect", domain+":443"],
            timeout=2,
            stderr=subprocess.STDOUT,
            input=b''
        ).decode("utf-8")
        match = re.search(r'O=([^,]+)', result)
        if match:
            return match.group(1).strip()
        else:
            return None

    except Exception as e:
        pass

def rdns_names(list_of_ips):
    response = []
    for ip in list_of_ips:
        try:
            result = subprocess.check_output(["nslookup", ip], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            pattern = r'name\s+=\s+([\w\.-]+)'
            matches = re.findall(pattern, result)
            response += matches
        except Exception as e:
            pass
    
    return response

def rtt_range(list_of_ips):
    min_rtt = inf
    max_rtt = -inf
    for ip in list_of_ips:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            start_time = time.time()
            # Do I have to change the port number?
            sock.connect((ip, 443))
            end_time = time.time()
            rtt = end_time - start_time
            min_rtt = min(rtt, min_rtt)
            max_rtt = max(rtt, max_rtt)
        except Exception as e:
            pass
    
    if min_rtt == inf or max_rtt == -inf:
        return None
    else:
        return [min_rtt, max_rtt]


def geo_locations(list_of_ips):
    response = set()
    with maxminddb.open_database('GeoLite2-City_20201103/GeoLite2-City.mmdb') as db:
        for ip in list_of_ips:
            # What do you do if city doesn't exist?
            try:
                location = db.get(ip)
                city = location["city"]["names"]["en"]
                subdivision = location["subdivisions"][0]["names"]["en"]
                country = location["country"]["names"]["en"]
                geo_location = city + ", " + subdivision + ", " + country
                response.add(geo_location)
            except Exception as e:
                pass
    return list(response)
            

# Check for correct number of parameters
if len(sys.argv) != 3:
    print("Incorrect number of parameters", file=sys.stderr)

# Check if input file in current directory
input_file_path = sys.argv[1]
output_file_path = sys.argv[2]

if not os.path.exists(input_file_path):
    print("Input file does not exist", file=sys.stderr)
    sys.exit()

# Read in domains
with open(input_file_path, "r") as input_file:
    web_domains = []
    for line in input_file:
        line = line.strip()
        web_domains.append(line)

# Create json dictionary
output_json = {}

# Create dictionaries for each domain
for domain in web_domains:
    output_json[domain] = {}

geo_locations(["165.124.85.22"])

# Log information
for domain in web_domains:
    output_json[domain]["scan_time"] = scan_time()
    ipv4 = ipv4_addresses(domain)
    output_json[domain]["ipv4_addresses"] = ipv4
    output_json[domain]["ipv6_addresses"] = ipv6_addresses(domain)
    output_json[domain]["http_server"] = http_server(domain)
    output_json[domain]["insecure_http"] = insecure_http(domain)
    output_json[domain]["redirect_to_https"] = redirect_to_https(domain)
    output_json[domain]["hsts"] = hsts(domain)
    output_json[domain]["tls_versions"] = tls_versions(domain)
    output_json[domain]["root_ca"] = root_ca(domain)
    output_json[domain]["rdns_names"] = rdns_names(ipv4)
    output_json[domain]["rtt_range"] = rtt_range(ipv4)
    output_json[domain]["geo_locations"] = geo_locations(ipv4)


with open(output_file_path, "w") as output_file:
    json.dump(output_json, output_file, sort_keys=True, indent=4)


