#!/usr/bin/env python3
"""
Send logs to XSIAM.

The script accept 3 arguments:

- `vendor` (``str``): The log vendor.
- `product` (``str``): The log product.
- `log` (``Path``): The path to the log file to parse and send to XSIAM.

Usage:

```bash
> ./send_logs_to_xsiam.py \
    -v Barracuda \
    -p "Email Protection" \
    ~/Downloads/2023-01-18-EmailSecurityService.log.txt


Reading file...
File contains 140 events
Sending events to XSIAM into Dataset 'barracuda_emailprotection_raw'...
```
"""

__author__ = "Kobbi"
__version__ = "0.1.0"
__license__ = "MIT"

import argparse
from pathlib import Path
from CommonServerPython import send_events_to_xsiam
import re


def transform_log(log: str) -> str:
    """
    Transforms the log line into a the expected XSIAM format
    """


def main(args: argparse.Namespace):
    """Main entry point of the app"""

    syslog_path = Path(args.log_path)

    if not syslog_path.exists():
        print(f"Path provided '{syslog_path}' doesn't exist. Terminating...")
        exit(1)

    vendor = str.lower(re.sub(r"[^a-zA-Z0-9]", "", args.vendor))
    product = str.lower(re.sub(r"[^a-zA-Z0-9]", "", args.product))

    print("Reading file...")
    # events = syslog_path.read_text().splitlines()
    # events = syslog_path.read_text()
    # print(f"File contains {len(events)} events")

    # for event in events:
    #     print(type(event[0]))

    print(f"Sending events to XSIAM into Dataset '{vendor}_{product}_raw'...")
    send_events_to_xsiam(events=events, vendor=vendor, product=product)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "log_path",
        help="""The path to the file containing the events/logs.
        The file is expected to have an event/log per line.""",
    )

    parser.add_argument("-v", "--vendor", action="store", dest="vendor", default="vendor")
    parser.add_argument("-p", "--product", action="store", dest="product", default="product")

    args = parser.parse_args()
    main(args)
