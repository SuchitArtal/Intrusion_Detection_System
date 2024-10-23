# Intrusion_Detection_System
This repository contains a Zeek script designed to detect DNS beaconing activity, which is a common indicator of malware communication.

# DNS Beaconing Detection with Zeek

This repository contains a Zeek script designed to detect DNS beaconing activity, which is a common indicator of malware communication.

## Files

- **`test.pcap`**: A sample PCAP file containing DNS traffic.
- **`dns-beacon.zeek`**: The Zeek script to analyze DNS traffic for potential beaconing activity.
- **`whitelist.csv`**: A CSV file specifying a list of domains to ignore during beaconing detection.

## Requirements

- **Zeek**: Ensure Zeek is installed on your system. The script is compatible with Zeek 6.2.1. You can download Zeek [here](https://zeek.org/get-zeek/).
  
  - Install Zeek and verify the version:
    ```bash
    zeek --version
    ```

- **PCAP File**: A packet capture file with DNS traffic, such as `test.pcap`, is required for testing the script.

## Whitelist CSV File

The `whitelist.csv` file specifies domains to exclude from beaconing detection. This file helps to filter out known trusted domains that may generate frequent DNS requests as part of normal network activity.

### CSV Format

The CSV file should contain a single column named `domain`, listing each whitelisted domain. Example:

```csv
domain
example.com
trusted-site.org
safe-domain.net
```

- **Note**: The first row must be the header domain, as it matches the field name in the Zeek script.

## Running the Zeek Script

-  Place `test.pcap` and whitelist.csv in the same directory as dns-beacon.zeek (or adjust the file paths in the script as needed).

- Run Zeek with the provided script to analyze the PCAP file:

```
zeek -C -r test.pcap dns-beacon.zeek
```
Zeek will process the DNS traffic and output potential beaconing activity while ignoring domains listed in `whitelist.csv.`

## Output
The script outputs logs detailing potential DNS beaconing events detected in the DNS traffic, including information such as:

- Source IP
- Queried domain
- Query frequency over specific intervals (1 minute, 5 minutes, and 30 minutes)

These logs help identify patterns that could indicate beaconing activity.

### Directory Structure
```
├── test.pcap
├── dns-beacon.zeek
└── whitelist.csv
```

## Troubleshooting
### Common Issues
- **Missing Dependencies**: Ensure Zeek is installed and paths are correctly set.
- **File Path Errors**: Verify file paths for `test.pcap` and `whitelist.csv` match those specified in the script or provided on the command line.


