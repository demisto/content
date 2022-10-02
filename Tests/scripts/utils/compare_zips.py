# function to compare two zip files


import argparse
import filecmp
import json
from pathlib import Path
import tempfile
from zipfile import ZipFile

import difflib
from contextlib import redirect_stdout
import dictdiffer

from ruamel.yaml import YAML

yaml = YAML()


def compare_zips(zip1: Path, zip2: Path, output_path: Path):
    """Compare two zip files content"""
    # extract zip files
    output_path.mkdir(parents=True, exist_ok=True)
    zip1_files = tempfile.mktemp()
    zip2_files = tempfile.mktemp()
    with ZipFile(zip1, "r") as zip1_content, ZipFile(zip2, "r") as zip2_content:
        # get the list of files in the zip files
        zip1_content.extractall(path=zip1_files)
        zip2_content.extractall(path=zip2_files)

    # compare the directories
    dir_compare = filecmp.dircmp(zip1_files, zip2_files)
    full_report_path = output_path / 'full_report.log'
    with open(full_report_path, 'w') as f:
        with redirect_stdout(f):
            dir_compare.report_full_closure()

    compare_files(dir_compare, zip1_files, zip2_files, output_path)


def compare_files(dir_compare: filecmp.dircmp[str], zip1_files: str, zip2_files: str, output_path):
    for file in dir_compare.common_files:
        if file not in dir_compare.same_files and file != 'signatures.sf':
            file_diff(output_path, zip1_files, zip2_files, file)
    for subdir in dir_compare.subdirs.values():
        compare_files(subdir, subdir.left, subdir.right, output_path / Path(subdir.left).name)


def file_diff_text(output_path_file: Path, file1_path: Path, file2_path: Path):
    output_path_file.unlink(missing_ok=True)

    with output_path_file.open('w') as f:
        with open(file1_path) as f1, open(file2_path) as f2:
            f1lines = f1.readlines()
            f2lines = f2.readlines()
            d = difflib.Differ()
            diffs = [x for x in d.compare(f1lines, f2lines) if x[0] in ('+', '-')]
            if diffs:
                f.writelines(diffs)


def file_diff(output_path: Path, zip1_files: str, zip2_files: str, file: str):
    output_path.mkdir(exist_ok=True, parents=True)
    try:
        file1_path = (Path(zip1_files) / file)
        file2_path = (Path(zip2_files) / file)
        file_diff_text(output_path / f'{file}-textdiff.log', file1_path, file2_path)
        if file1_path.suffix == '.yml':
            load_func = yaml.load
        elif file1_path.suffix == '.json':
            load_func = json.load
        else:
            print(f'not yaml or json: {output_path / file}. continue')
            return
        output_dict_diff = output_path / f'{file}-dictdiff.json'
        output_dict_diff.unlink(missing_ok=True)
        with open(output_dict_diff, 'w') as f:
            with open(file1_path) as f1, open(file2_path) as f2:
                diff_found = list(dictdiffer.diff(load_func(f1), load_func(f2)))
                json.dump(diff_found, f, indent=4)
    except Exception as e:
        print(f'could not diff files {file}: {e}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--zip-id-set', help='id_set zip file to compare')
    parser.add_argument('--zip-graph', help='graph_id_set zip file to compare')
    parser.add_argument('--output-path', help='Output path')
    args = parser.parse_args()
    zip_id_set = Path(args.zip_id_set)
    zip_graph = Path(args.zip_graph)
    output_path = Path(args.output_path)
    output_path.mkdir(exist_ok=True, parents=True)
    # compare directories
    dir_cmp = filecmp.dircmp(zip_id_set, zip_graph)
    dir_cmp.report_full_closure()
    for file in dir_cmp.common_files:
        pack = file.removesuffix('.zip')
        compare_zips(zip_id_set / file, zip_graph / file, output_path / pack)
