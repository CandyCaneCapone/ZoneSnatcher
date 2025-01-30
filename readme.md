# ZoneSnatcher

A tool to check for DNS zone transfer vulnerabilities in a domain or a list of domains. It attempts to identify open DNS servers that are susceptible to zone transfers, which could potentially expose sensitive subdomain information.

![Example](https://github.com/CandyCaneCapone/ZoneSnatcher/blob/main/example.png?raw=true)

## Features

- Supports checking a single domain or a list of domains.
- Multithreaded for faster execution with configurable thread count.
- Option to save results to a file.
- Custom DNS servers for querying.
- Zone transfer vulnerability detection.

## Installation

To use the DNS Zone Transfer Vulnerability Scanner, you'll need to have Python 3.x installed along with the required dependencies.

1. Clone this repository:

   ```bash
   git clone https://github.com/CandyCaneCapone/ZoneSnatcher.git
   cd ZoneSnatcher
   ```

2. Install the required Python dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

```bash
python zonesnatcher.py -h
```

This will display help for you.

```bash
usage: zonesnatcher.py [-h] [-d DOMAIN] [-l LIST] [-o OUTPUT] [-t THREADS]

DNS Zone Transfer Vulnerability Scanner

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Target domain to check for zone transfer
  -l LIST, --list LIST  List of target domains to check for zone transfer
  -o OUTPUT, --output OUTPUT
                        Save results to a file
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 5)

```
