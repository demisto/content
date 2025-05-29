from collections import defaultdict
import operator
import xml.etree.ElementTree as ET
from pathlib import Path
import csv


class PackNameParseError(Exception):
    def __init__(self, value: str) -> None:
        self.value = value
        super().__init__(
            f"Cannot parse pack name out of {value}, expected Packs.<pack_name>.more_parts"
        )


def parse_pack_name(class_name: str):
    # parses Packs.IPINFO.Integrations.ipinfo_v2.ipinfo_v2_test into IPINFO
    if (
        (not class_name.startswith("Packs."))
        or len(parts := class_name.split(".")) < 3
        or not (parsed_pack_name := parts[1])
    ):
        raise PackNameParseError(class_name)
    return parsed_pack_name


def parse_xml(path: Path = Path("report_pytest.xml")) -> dict[str, float]:
    pack_times: defaultdict[str, float] = defaultdict(int)

    for suite in ET.parse(path).getroot().findall("testsuite"):
        for case in suite.findall("testcase"):
            pack_name = parse_pack_name(case.attrib["classname"])
            pack_times[pack_name] += float(case.attrib["time"])
    return dict(
        sorted(
            pack_times.items(),
            key=operator.itemgetter(1),
            reverse=True,  # Sorted by descending duration
        )
    )


def write_csv(pack_times: dict[str, float], output_path: Path) -> None:
    with output_path.open("w", newline="") as file:
        writer = csv.DictWriter(
            file,
            ["pack", "duration"],
        )
        writer.writeheader()
        writer.writerows(
            [
                {
                    "pack": pack,
                    "duration": str(
                        round(duration, 2)
                    ),  # str avoids floating point percision
                }
                for pack, duration in pack_times.items()
            ]
        )


if __name__ == "__main__":
    pack_times = parse_xml()
    write_csv(pack_times, Path("packwise_pytest_time.csv"))
