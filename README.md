# TDARE-Analyzer-Evtx-To-Json

# TDARE EVTX to JSON Converter

A lightweight Python command-line utility for converting Windows Event Log (`.evtx`) files into structured JSON.

Developed as part of the **TDARE cybersecurity ecosystem**, this tool helps security analysts extract, organize, and prepare Windows event records for further investigation and security analysis.

## Features

- Convert Windows `.evtx` files into structured JSON.
- Export all available events or filter by security-relevant Event IDs.
- Support custom Event ID selection.
- Extract event timestamps, providers, channels, computer names, and EventData.
- Preserve additional event metadata.
- Optionally include original XML for deeper inspection.
- Generate conversion statistics and Event ID summaries.
- Process files locally without uploading logs to an external service.

## Supported Event Categories

The security-focused preset includes selected events from the following categories:

| Category | Example Event IDs |
|---|---|
| Authentication & Logon | 4624, 4625, 4634, 4648, 4672, 4776 |
| Account Management | 4720, 4722, 4724, 4726, 4732, 4733 |
| Process Activity | 4688, 4689 |
| System & Security | 1102, 4616, 4719, 4697 |
| Windows Firewall | 4946, 4947, 4948, 5152, 5156, 5157 |
| Object Access | 4656, 4657, 4660, 4663 |
| PowerShell | 400, 403, 600, 800, 4103, 4104 |
| Remote Desktop | 1149, 21, 22, 23, 24, 25 |

**Note:** These are selected Windows Event IDs, not a complete list of Windows security events. Their meaning and availability depend on the event channel, provider, and system audit configuration.

## Requirements

- Python 3.9+
- Windows, Linux, or Kali Linux
- `python-evtx`

## Installation

Clone the repository:

```bash
git clone https://github.com/a-skera/TDARE-EVTX-JSON-Converter.git
cd TDARE-EVTX-JSON-Converter
```

Create a virtual environment:

**Windows:**

```powershell
py -m venv venv
.\venv\Scripts\activate
```

**Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### 1. Export all events

```bash
python converter.py -i Security.evtx -o all_events.json
```

### 2. Export security-relevant events

```bash
python converter.py -i Security.evtx -o security_events.json -m security
```

### 3. Export custom Event IDs

```bash
python converter.py -i Security.evtx -o selected.json -m custom --ids 4624,4625,4688,4720
```

### 4. Include original XML

```bash
python converter.py -i Security.evtx -o forensic.json --include-xml
```

### 5. Display available options

```bash
python converter.py --help
```

## Output Format

The converter produces structured JSON containing conversion metadata, statistics, and extracted events.

Example:

```json
{
  "EventID": 4625,
  "TimeCreated": "2026-11-10T10:00:00Z",
  "Computer": "WORKSTATION-01",
  "Channel": "Security",
  "Provider": "Microsoft-Windows-Security-Auditing",
  "EventData": {
    "TargetUserName": "administrator",
    "IpAddress": "192.168.1.50",
    "LogonType": "3"
  }
}
```

The complete output contains an `events` array alongside conversion metadata and statistics.

## Integration with TDARE Analyzer

This utility is designed to help users prepare Windows Event Log files for analysis through the TDARE Analyzer platform.

The current public analyzer supports a defined subset of Windows Security events. Additional event categories and analysis capabilities are being developed.

Converted JSON files may contain more events than the current analyzer can actively interpret.

## Privacy

All conversion takes place locally on the user's machine. The utility does not require an external API or upload event logs to TDARE.

Users remain responsible for handling exported logs securely, as they may contain sensitive information.

## Limitations

- The utility currently supports Windows EVTX files.
- Event availability depends on the source system's logging configuration.
- Some event records may contain provider-specific or complex XML structures.
- Exporting an event does not establish that it is malicious or suspicious.
- The security preset is not a threat-detection engine.

## Project

** TDARE - Analyzer is a lightweight demo of the main AI-SOC-Platform TDARE — Threat Detection and Automatic Response integrated with Reverse Engineering. **

Website: [TDARE Analyzer] (https://lightweight-tdare-analyzer.tdare-cys.workers.dev/)

Contact: tdare.cys@gmail.com

## License

Specify the repository's chosen open-source license here before publishing.

---

Developed by TDARE.
