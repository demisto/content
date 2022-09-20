# function to compare two zip files


import argparse
import filecmp
from pathlib import Path
from zipfile import ZipFile


def compare_zips(zip1: Path, zip2: Path):
    """Compare two zip files content"""
    # extract zip files
    with ZipFile(zip1, "r") as zip1_content, ZipFile(zip2, "r") as zip2_content:
        # get the list of files in the zip files
        zip1_content.extractall()
        zip2_content.extractall()

    # compare the directories
    dir_compare = filecmp.dircmp(zip1.stem, zip2.stem)
    dir_compare.report_full_closure()
    for file in dir_compare.common_files:
        if file.endswith('json'):
            # compare the json files
            pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('zip1', help='First zip file to compare')
    parser.add_argument('zip2', help='Second zip file to compare')
    args = parser.parse_args()
    compare_zips(Path(args.zip1), Path(args.zip2))
    # use argparse
