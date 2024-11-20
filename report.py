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

with open(output_file_path, "w", encoding="utf-8") as f:
    for web_domain, data in json_data.items():
        # Create a table
        f.write(f"Domain: {web_domain}\n")
        f.write("=" * (len(web_domain) + 8) + "\n")

        table = tt.Texttable()
        table.set_cols_align(["l", "l"])
        table.set_cols_valign(["m", "m"])
        table.header(["Field", "Value"])

        for key, value in data.items():
            if isinstance(value, list):
                value = "\n".join(map(str, value))
            table.add_row([key, value])
        
        f.write(table.draw() + "\n\n")