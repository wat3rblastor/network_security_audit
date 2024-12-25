# Network Security Audit

This project is a Python script that gathers networking information of your favorite websites.

First, you run scan.py to retrieve the networking information. Then, your run report.py to display the information in a user-friendly format.

## Installation

First, create a Python virtual environment. Then, run 
```bash
pip3 install -r requirements.txt
```

## Usage

```python
python3 scan.py popular_websites.txt scan_results.json
python3 report.py scan_results.json report_results.txt
```

Be patient when running scan.py. It will take awhile. 

## Modification
You are able to modify the website urls in popular_websites.txt. Otherwise, you can create your own txt file
and add your own website urls. Then, run the commands
```python
python3 scan.py [your_txt_file].txt scan_results.json
python3 report.py scan_results.json report_results.txt
```
