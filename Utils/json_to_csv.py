import argparse
import os
from typing import Optional

import pandas as pd
import json
import logging
from Tests.scripts.utils.log_util import install_logging


def list_to_dataframe(
        json_record: dict,
        starting_index: int,
        col_name: Optional[str] = None,
        col_val: Optional[str] = None) -> pd.DataFrame:
    ending_index = starting_index + len(json_record)
    df = pd.DataFrame.from_records(json_record, index=range(starting_index, ending_index))
    if col_name and col_val:
        df[col_name] = col_val
    return df


def create_csv_file_from_json(input_file: str, output_file: str, custom_column_name=None):
    if not os.path.isfile(input_file):
        logging.error(f'input file "{input_file}" was not found')
        return
    with open(input_file, 'r') as f:
        json_data = json.load(f)[0]  # TODO: Handle list properly
    dataframes = []
    index = 0
    if isinstance(json_data, dict):
        for record_key, json_record in json_data.items():
            if not isinstance(json_record, list) or len(json_data) == 0:
                if not isinstance(json_record, dict):
                    continue
                json_record = [json_record]
            dataframes.append(list_to_dataframe(json_record, index, col_name=custom_column_name, col_val=record_key))
            index += len(json_record)
    if dataframes:
        results_df = pd.concat(dataframes)
        results_df.to_csv(output_file, index=False)
    else:
        logging.error('no csv could be extracted from input file. Creating empty file')
        open(output_file).close()


def option_handler():
    parser = argparse.ArgumentParser(description='Transform a file containing a json to .')
    parser.add_argument('-i', '--input_file', help='The path to the file to transform.', required=True)
    parser.add_argument('-o', '--output_file', help='The output path for the CSV result.', required=True)
    parser.add_argument('-c', '--custom_column_name', help='Custom column to be used for the CSV result.')

    options = parser.parse_args()

    return options


def main():
    install_logging('Json_To_CSV.log')
    options = option_handler()
    input_file = options.input_file
    output_file = options.output_file
    custom_column_name = options.custom_column_name
    create_csv_file_from_json(input_file, output_file, custom_column_name)


if __name__ == "__main__":
    main()
