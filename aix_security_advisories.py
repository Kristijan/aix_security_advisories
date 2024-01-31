#!/usr/bin/env python
'''Produces a table of AIX/VIOS advisories'''

# Imports
import argparse
import json
import sys
from pathlib import Path

from datetime import date, timedelta
import requests
from rich.console import Console
from rich.table import Table
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

# Set the base path to be used for reading files from the local filesystem
base_path = Path(__file__).parent

# Setup argument parser
parser = argparse.ArgumentParser(description="Produces a table of AIX/VIOS advisories")
parser.add_argument('-d', '--days',
                    action='store',
                    default=14,
                    type=int,
                    help='''Show advisories issued and/or updated in the past number days.''')
parser.add_argument('-f', '--file',
                    type=Path,
                    help='''File containing JSON data.''')
parser.add_argument('-i', '--insecure',
                    action='store_false',
                    default=True,
                    help='''Ignore HTTPS insecure request warnings.''')
parser.add_argument('-u', '--urls',
                    action='store_true',
                    default=False,
                    help='''Show only URLs to download fixes.''')

# Parse command line args
results = parser.parse_args()

# Get JSON data, either from file or URL
if results.file:
    # Get JSON from file
    file = (base_path / results.file).resolve()
    try:
        with open(file, encoding='utf-8', mode='r') as jsondata:
            data = json.load(jsondata)
    except (NameError, FileNotFoundError):
        print(f'Error: {file} file not found.')
        sys.exit(1)
else:
    # Get JSON from URL
    IBM_URL = 'https://esupport.ibm.com/customercare/flrt/doc?page=aparJSON'
    if not results.insecure:
        disable_warnings(InsecureRequestWarning)
    try:
        response = requests.get(IBM_URL, verify=results.insecure, timeout=10)
        if response.status_code == 200:
            data = json.loads(response.text)
        else:
            print(f"HTTP status code {response.status_code} returned from {IBM_URL}")
            sys.exit(1)
    except Exception as error:
        print("An exception occurred:", type(error).__name__)
        sys.exit(1)

# Create sorted (by date) list advisories
advisories = []
for advisory in data:
    if advisory['type'] == "sec":
        date_issued = date(year=int(str(advisory['issued'])[:-4]),
                           month=int(str(advisory['issued'])[4:6]),
                           day=int(str(advisory['issued'])[6:8]))
        if advisory['updated'] != 'null':
            date_updated = date(year=int(str(advisory['updated'])[:-4]),
                                month=int(str(advisory['updated'])[4:6]),
                                day=int(str(advisory['updated'])[6:8]))
            date_updated_formatted = date_updated.strftime("%d/%m/%Y")
        else:
            date_updated_formatted = 'N/A'
        # By default, only show advisories from the past 14 days
        if (
            isinstance(date_updated_formatted, date) and
            (date.today() - timedelta(days=results.days)) <= date_updated <= date.today()
        ):
            advisories.append({"issued": date_issued,
                            "updated": date_updated_formatted,
                            "apAbstract": advisory['apAbstract'],
                            "bulletinUrl": advisory['bulletinUrl'],
                            "reboot": advisory['reboot'],
                            "cvss": advisory['cvss']})
        elif (date.today() - timedelta(days=results.days)) <= date_issued <= date.today():
            advisories.append({"issued": date_issued,
                            "updated": date_updated_formatted,
                            "apAbstract": advisory['apAbstract'],
                            "downloadUrl": advisory['downloadUrl'],
                            "bulletinUrl": advisory['bulletinUrl'],
                            "reboot": advisory['reboot'],
                            "cvss": advisory['cvss']})
advisories_sorted = sorted(advisories, key=lambda d: d['issued'])

# Table headers
table = Table(title='AIX/VIOS Security Advisories', show_lines=True)
if not results.urls:
    table.add_column("Issued")
    table.add_column("Updated")
    table.add_column("Abstract")
    table.add_column("URL")
    table.add_column("Reboot")
    table.add_column("CVE")
    table.add_column("CVSS")
else:
    table.add_column("URL")

# Table contents
for advisory in advisories_sorted:
    table_cve  = Table(show_header=False, box=None)
    table_cvss = Table(show_header=False, box=None)
    if len(advisory['cvss']) >= 1:
        for cve in advisory['cvss']:
            table_cve.add_row(cve.split(":")[0])
            try:
                cve_score = cve.split(":")[1]
                if cve_score:
                    # Highlight in red, CVSS scores greater than or equal to 8
                    if float(cve_score) >= 8:
                        table_cvss.add_row(f'[red]{cve_score}[/red]')
                    else:
                        table_cvss.add_row(cve_score)
                else:
                    table_cvss.add_row('N/A')
            except IndexError:
                table_cvss.add_row('N/A')
    else:
        table_cve.add_row('N/A')
        table_cvss.add_row('N/A')
    if results.urls:
        table.add_row(advisory['downloadUrl'])
    else:
        table.add_row(advisory['issued'].strftime("%d/%m/%Y"),
                      advisory['updated'], advisory['apAbstract'],
                      advisory['bulletinUrl'],
                      advisory['reboot'],
                      table_cve,
                      table_cvss)

# Print table
console = Console()
console.print(table)
