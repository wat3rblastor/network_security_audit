import json
import os
import sys
import texttable as tt

# Check for correct number of parameters
if len(sys.argv) != 3:
    print("Incorrect number of parameters", file=sys.stderr)

# Check if input file in current directory
input_file_path = sys.argv[1]
output_file_path = sys.argv[2]

if not os.path.exists(input_file_path):
    print("Input file does not exist", file=sys.stderr)
    sys.exit()

# Read in data
with open(input_file_path, "r") as f:
    json_data = json.load(f)

total_no_domains = len(json_data.keys())


complete_information_tables = []
rtt_ranges = []
root_ca_occurences = {}
web_server_occurences = {}
# Category -> # number domains supported
domains_supported = {
    "SSLv2": 0,
    "SSLv3": 0,
    "TLSv1.0": 0,
    "TLSv1.1": 0,
    "TLSv1.2": 0,
    "TLSv1.3": 0,
    "Plain HTTP": 0,
    "HTTPS Redirect": 0,
    "HSTS": 0,
    "IPv6": 0
}

for web_domain, data in json_data.items():

    # Table for complete_information_tables
    table = tt.Texttable()
    table.set_cols_align(["l", "l"])
    table.set_cols_valign(["m", "m"])
    table.header(["Field", "Value"])

    for key, value in data.items():
        # Sort information
        if key == "rtt_range":
            # Append min_rtt value, domain name, rtt_range
            rtt_ranges.append([value[0], web_domain, value])
        elif key == "root_ca":
            if value not in root_ca_occurences:
                root_ca_occurences[value] = 1
            else:
                root_ca_occurences[value] += 1
        elif key == "http_server":
            if value not in web_server_occurences:
                web_server_occurences[value] = 1
            else:
                web_server_occurences[value] += 1
        elif key == "tls_versions":
            versions = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
            for version in versions:
                if version in value:
                    domains_supported[version] += 1 
        elif key == "insecure_http" and value == True:
            domains_supported["Plain HTTP"] += 1
        elif key == "redirect_to_https" and value == True:
            domains_supported["HTTPS Redirect"] += 1
        elif key == "hsts" and value == True:
            domains_supported["HSTS"] += 1
        elif key == "ipv6_addresses" and value != []:
            domains_supported["IPv6"] += 1
        
        # Format value
        if isinstance(value, list):
            value = "\n".join(map(str, value)) 

        # Append row to complete information table
        table.add_row([key, value])

    complete_information_tables.append([web_domain, table])

# Write everything to output file
with open(output_file_path, "w", encoding="utf-8") as f:
    # Write complete information tables
    f.write("All Information\n\n")
    f.write("=" * 50 + "\n")
    for web_domain, table in complete_information_tables:
        f.write(f"Domain: {web_domain}\n")
        f.write(table.draw() + "\n\n")

    # Write table showing RTT ranges of all domain, sorted by min RTT
    table = tt.Texttable()
    table.set_cols_align(["l", "l"])
    table.set_cols_valign(["m", "m"])
    table.header(["Domain", "RTT Range"])
    rtt_ranges.sort()
    for item in rtt_ranges:
        table.add_row([item[1], item[2]])
    f.write("RTT Ranges for all Domains\n")
    f.write("=" * 50 + "\n")
    f.write(table.draw() + "\n\n")

    # Write table showing number of occurrences from each root certificate authority
    table = tt.Texttable()
    table.set_cols_align(["l", "l"])
    table.set_cols_valign(["m", "m"])
    table.header(["Root Certificate Authority", "Number of Occurences"])
    root_ca_occurences_array = [[key, value] for key, value in root_ca_occurences.items()]
    root_ca_occurences_array.sort(key=lambda x: x[1], reverse=True)
    for item in root_ca_occurences_array:
        table.add_row([item[0], item[1]])
    f.write("Number of Occurences of Observed Root Certificate Authority\n")
    f.write("=" * 50 + "\n")
    f.write(table.draw() + "\n\n")

    # Write table showing number of occurrences from each web server
    table = tt.Texttable()
    table.set_cols_align(["l", "l"])
    table.set_cols_valign(["m", "m"])
    table.header(["Web Server", "Number of Occurences"])
    web_server_occurences_array = [[key, value] for key, value in web_server_occurences.items()]
    web_server_occurences_array.sort(key=lambda x: x[1], reverse=True)
    for item in web_server_occurences_array:
        table.add_row([item[0], item[1]])
    f.write("Number of Occurences of Web Servers\n")
    f.write("=" * 50 + "\n")
    f.write(table.draw() + "\n\n")

    # Write table showing network feature and number of domains supporting
    table = tt.Texttable()
    table.set_cols_align(["l", "l"])
    table.set_cols_valign(["m", "m"])
    table.header(["Network Feature", "Percentage of Number of Domains Supporting (%)"])
    for feature, no_domains_supporting in domains_supported.items():
        percentage = no_domains_supporting / total_no_domains * 100
        table.add_row([feature, percentage])
    f.write("Percentage of Domains Supporting Network Feature\n")
    f.write("=" * 50 + "\n")
    f.write(table.draw() + "\n\n")

