# function to compare two zip files


import argparse
import filecmp
from pathlib import Path
import tempfile
from zipfile import ZipFile

import difflib
from contextlib import redirect_stdout


def compare_zips(zip1: Path, zip2: Path, output_path: Path):
    """Compare two zip files content"""
    # extract zip files
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

    compare_files(dir_compare, zip1_files, zip2_files)


def compare_files(dir_compare: filecmp.dircmp[str], zip1_files: str, zip2_files: str):
    for file in dir_compare.common_files:
        file_diff(output_path, zip1_files, zip2_files, file)
    for subdir in dir_compare.subdirs.values():
        compare_files(subdir, zip1_files, zip1_files)


def file_diff(output_path: Path, zip1_files: str, zip2_files: str, file: str):
    try:
        file1_content = (Path(zip1_files) / file).read_text()
        file2_content = (Path(zip2_files) / file).read_text()
        d = difflib.Differ()
        with open(output_path / file) as f:
            f.write(d.compare(file1_content, file2_content))
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
        pack = file.strip('.zip')
        compare_zips(zip_id_set / file, zip_graph / file, output_path / pack)
