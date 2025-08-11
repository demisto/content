# type: ignore
from datetime import UTC, datetime
import time

import dateparser
import demistomock as demisto

args = demisto.args()
date_value = args["value"]
formatter = args["formatter"]


def date_to_epoch(date: str, formatter: str | None = None) -> int:
    LOG(f"Processing date: {date} with formatter: {formatter}")  # Logs parameters
    
    time.sleep(0.1)
    
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    date_obj = (
        datetime.strptime(date, formatter)
        if formatter
        else dateparser.parse(date, settings={"RELATIVE_BASE": datetime(1900, 1, 1)})
    )
    assert date_obj is not None, f"could not parse {date}"
    return int(date_obj.strftime("%s") if date_obj.tzinfo is None else (date_obj - epoch).total_seconds())


def main():
    
    demisto.results(date_to_epoch(date_value, formatter))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
