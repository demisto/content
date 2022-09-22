# function to compare two zip files


import argparse
import filecmp
import json
from pathlib import Path
from zipfile import ZipFile

import dictdiffer
import yaml


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
        if (is_json := file.endswith('json')) or file.endswith('yaml'):
            # compare the json files
            parse_func = json.load if is_json else yaml.load
            with open(Path(zip1.stem) / file) as file1, open(Path(zip2.stem) / file) as file2:
                dct1 = parse_func(file1)
                dct2 = parse_func(file2)
                if dct1 != dct2:
                    print(f'JSON files {file} are different')
                    print(dictdiffer.diff(dct1, dct2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--zip-id-set', help='id_set zip file to compare')
    parser.add_argument('--zip-graph', help='graph_id_set zip file to compare')
    args = parser.parse_args()
    zip_id_set = Path(args.zip_id_set)
    zip_graph = Path(args.zip_graph)
    # compare directories
    dir_cmp = filecmp.dircmp(zip_id_set, zip_graph)
    dir_cmp.report_full_closure()
    for file in dir_cmp.common_files:
        compare_zips(zip_id_set / file, zip_graph / file)
