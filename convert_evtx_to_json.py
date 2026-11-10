import argparse
import json
import sys
import xml.etree.ElementTree as ET

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from Evtx.Evtx import Evtx


# ============================================================
# TDARE EVTX TO JSON CONVERTER
# General-purpose Windows Event Log extraction utility
# ============================================================

VERSION = "1.0.0"

# Security-relevant Windows Event IDs.
# These are useful presets, not an exhaustive detection list.
SECURITY_EVENT_IDS = {
    # Authentication and logon
    4624, 4625, 4634, 4647, 4648, 4672, 4776,

    # Account management
    4720, 4722, 4723, 4724, 4725, 4726,
    4732, 4733, 4756, 4757,

    # Process activity
    4688, 4689,

    # System and security changes
    1102, 4616, 4719, 4697,

    # Windows Firewall
    4946, 4947, 4948, 5152, 5156, 5157,

    # Object access
    4656, 4657, 4660, 4663,

    # PowerShell
    400, 403, 600, 800, 4103, 4104,

    # Remote Desktop
    1149, 21, 22, 23, 24, 25,
}

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def local_name(tag):
    """Return an XML tag without its namespace."""
    return tag.split("}", 1)[-1]


def get_child_text(parent, child_name):
    """Get the text of a direct XML child."""
    if parent is None:
        return None

    for child in parent:
        if local_name(child.tag) == child_name:
            return child.text

    return None


def extract_event_data(event_data_element):
    """Extract named EventData fields without discarding duplicates."""
    result = {}

    if event_data_element is None:
        return result

    unnamed_counter = 0

    for element in event_data_element:
        tag = local_name(element.tag)

        if tag == "Data":
            name = element.attrib.get("Name")

            if not name:
                unnamed_counter += 1
                name = f"Data_{unnamed_counter}"

            value = element.text or ""

        else:
            name = tag
            value = element.text or ""

        # Preserve duplicate field names rather than overwriting them.
        if name in result:
            if not isinstance(result[name], list):
                result[name] = [result[name]]
            result[name].append(value)
        else:
            result[name] = value

    return result


def element_to_string(element):
    """Serialize an XML element while preserving its content."""
    if element is None:
        return None

    return ET.tostring(element, encoding="unicode")


def parse_event(xml_content, include_xml=False):
    """Convert one Windows EVTX record into a structured dictionary."""
    root = ET.fromstring(xml_content)

    system = None
    event_data_element = None
    user_data_element = None

    for child in root:
        tag = local_name(child.tag)

        if tag == "System":
            system = child
        elif tag == "EventData":
            event_data_element = child
        elif tag == "UserData":
            user_data_element = child

    if system is None:
        raise ValueError("Event does not contain a System section")

    provider_element = next(
        (child for child in system if local_name(child.tag) == "Provider"),
        None
    )

    time_element = next(
        (child for child in system if local_name(child.tag) == "TimeCreated"),
        None
    )

    event_id_text = get_child_text(system, "EventID")

    if event_id_text is None:
        raise ValueError("Event ID is missing")

    try:
        event_id = int(event_id_text)
    except ValueError:
        event_id = event_id_text

    event = {
        "EventID": event_id,
        "TimeCreated": (
            time_element.attrib.get("SystemTime")
            if time_element is not None else None
        ),
        "Computer": get_child_text(system, "Computer"),
        "Channel": get_child_text(system, "Channel"),
        "EventRecordID": get_child_text(system, "EventRecordID"),
        "Version": get_child_text(system, "Version"),
        "Level": get_child_text(system, "Level"),
        "Task": get_child_text(system, "Task"),
        "Opcode": get_child_text(system, "Opcode"),
        "Keywords": get_child_text(system, "Keywords"),
        "Provider": (
            provider_element.attrib.get("Name")
            if provider_element is not None else None
        ),
        "ProviderGuid": (
            provider_element.attrib.get("Guid")
            if provider_element is not None else None
        ),
        "EventData": extract_event_data(event_data_element),
    }

    if user_data_element is not None:
        event["UserDataXML"] = element_to_string(user_data_element)

    if include_xml:
        event["RawXML"] = xml_content

    return event


def convert_evtx(input_path, output_path, mode, custom_ids, include_xml):
    """Read an EVTX file, apply the selected filter, and export JSON."""

    input_file = Path(input_path)
    output_file = Path(output_path)

    if not input_file.is_file():
        raise FileNotFoundError(f"Input file not found: {input_file}")

    if input_file.suffix.lower() != ".evtx":
        raise ValueError("Input file must have an .evtx extension")

    if mode == "custom" and not custom_ids:
        raise ValueError("Custom mode requires at least one Event ID")

    selected_ids = set()

    if mode == "security":
        selected_ids = SECURITY_EVENT_IDS
    elif mode == "custom":
        selected_ids = set(custom_ids)

    events = []
    total_records = 0
    skipped_records = 0
    event_counts = Counter()

    print("\n==============================================")
    print("       TDARE EVTX TO JSON CONVERTER")
    print("==============================================")
    print(f"[+] Input:  {input_file}")
    print(f"[+] Mode:   {mode.upper()}")
    print("[+] Reading EVTX records...\n")

    with Evtx(str(input_file)) as log:
        for record in log.records():
            total_records += 1

            try:
                xml_content = record.xml()
                event = parse_event(xml_content, include_xml)

                event_id = event["EventID"]

                if selected_ids and event_id not in selected_ids:
                    continue

                events.append(event)
                event_counts[str(event_id)] += 1

            except Exception as error:
                skipped_records += 1
                print(
                    f"[!] Skipped record {total_records}: {error}",
                    file=sys.stderr
                )

    result = {
        "tool": "TDARE EVTX to JSON Converter",
        "version": VERSION,
        "source_file": input_file.name,
        "conversion_time": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "statistics": {
            "total_records_read": total_records,
            "events_exported": len(events),
            "records_skipped": skipped_records,
            "event_id_counts": dict(sorted(event_counts.items())),
        },
        "events": events,
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)

    print("\n==============================================")
    print("             CONVERSION SUMMARY")
    print("==============================================")
    print(f"Total records read: {total_records}")
    print(f"Events exported:    {len(events)}")
    print(f"Records skipped:    {skipped_records}")
    print(f"Output file:        {output_file}")

    print("\nExported Event IDs:")
    for event_id, count in sorted(event_counts.items()):
        print(f"  Event ID {event_id}: {count}")

    print("\n[+] Conversion completed.\n")


def parse_event_ids(value):
    """Parse comma-separated Event IDs."""
    try:
        return [int(item.strip()) for item in value.split(",")]
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Event IDs must be comma-separated numbers, e.g. 4624,4625,4688"
        )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "TDARE EVTX to JSON Converter - "
            "Extract Windows Event Logs into structured JSON."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument(
        "-i", "--input",
        required=True,
        help="Input EVTX file"
    )

    parser.add_argument(
        "-o", "--output",
        default="tdare_export.json",
        help="Output JSON file"
    )

    parser.add_argument(
        "-m", "--mode",
        choices=["all", "security", "custom"],
        default="all",
        help="Export all events, selected security events, or custom IDs"
    )

    parser.add_argument(
        "--ids",
        type=parse_event_ids,
        help="Custom Event IDs, e.g. 4624,4625,4688"
    )

    parser.add_argument(
        "--include-xml",
        action="store_true",
        help="Include original event XML in the JSON output"
    )

    args = parser.parse_args()

    try:
        convert_evtx(
            input_path=args.input,
            output_path=args.output,
            mode=args.mode,
            custom_ids=args.ids,
            include_xml=args.include_xml
        )

    except Exception as error:
        print(f"\n[ERROR] {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
