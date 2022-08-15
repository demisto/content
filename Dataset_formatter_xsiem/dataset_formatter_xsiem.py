from datetime import datetime
import pandas as pd
from abc import ABC, abstractmethod
import math
import re
from pathlib import Path
import argparse
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class Formatter(ABC):
    @property
    @abstractmethod
    def name(self):
        pass

    @property
    @abstractmethod
    def regex(self):
        pass

    def is_format(self, data):
        if isinstance(data, str):
            match = re.search(self.regex, data)
            return match

        return None

    @abstractmethod
    def convert_to_xsiem_format(self, col):
        pass


class TimeFormat1(Formatter):

    @property
    def name(self):
        return 'TimeFormat example - Aug 3rd 2022 18:40:17'

    @property
    def regex(self):
        return r"\w{3} \d{1,2}(st|nd|rd|th) \d{4} (\d{2}:){2}\d{2}"

    def convert_to_xsiem_format(self, col):
        res_list = []
        for time_element in col:
            if isinstance(time_element, float):
                res_list.append('2003-01-01T00:00:00')
            else:
                time_element = self.replace_day_with_number(time_element)
                formated_time = datetime.strptime(time_element, '%b %d %Y %H:%M:%S')
                string_time = formated_time.strftime('%Y-%m-%dT%H:%M:%S')
                res_list.append(string_time)

        return res_list

    @staticmethod
    def replace_day_with_number(date: str):
        """
        Args:
            - a date of type Aug 3rd 2022 18:40:17

        Returns:
            - The same date witout the (st|nd|rd|th)
        """
        return re.sub(r'(st|nd|rd|th)', r'', date)


class TimeFormat2(Formatter):

    @property
    def name(self):
        return 'TimeFormat2 example - 2022-08-03T15:40:16.986Z'

    @property
    def regex(self):
        return r"\d{4}(-\d{2}){2}T(\d{2}:){2}\d{2}.\d{3}Z"

    def convert_to_xsiem_format(self, col):
        res_list = []
        for time_element in col:
            if isinstance(time_element, float):
                res_list.append('2003-01-01T00:00:00.000Z')
            else:
                res_list.append(time_element)

        return res_list


class JsonFormat(Formatter):

    @property
    def name(self):
        return 'Json Format - {example}'

    @property
    def regex(self):
        return r"^{.*}$"

    def convert_to_xsiem_format(self, col):
        res_list = []
        for cell in col:
            if isinstance(cell, float) and math.isnan(cell):
                res_list.append('{}')
            else:
                cell = cell.replace('\\', '\\\\')
                res_list.append(cell)

        return res_list


class JsonArrayFormat(Formatter):

    @property
    def name(self):
        return 'Json Array Format - []'

    @property
    def regex(self):
        return r"^\[.*\]$"

    def convert_to_xsiem_format(self, col):
        res_list = []
        for cell in col:
            if isinstance(cell, float) and math.isnan(cell):
                res_list.append('[]')
            else:
                cell = cell.replace('\\', '\\\\')
                res_list.append(cell)

        return res_list


class FormatManager:
    def __init__(self):
        self.format_type: Formatter = None
        self.formatters: list[Formatter] = [TimeFormat1(), JsonFormat(), TimeFormat2(), JsonArrayFormat()]

    def find_col_format(self, col: list):
        """
        If a format was detected it puts that format class in self.format_type
        else it sets the self.format_type to None

        Args:
            - One of the dataFrame cols

        Returns:
            - None
        """
        for val in col:
            for formatter in self.formatters:
                if formatter.is_format(val):
                    self.format_type = formatter
                    return 
        
        self.format_type = None

    def convert_to_xsiem_format(self, col):
        """
        Args:
            - One of the dataFrame cols

        Return:
            - A list of the formatted col
        """
        return self.format_type.convert_to_xsiem_format(col)

    def formatter_name(self):
        return self.format_type.name


def open_input_file(path: Path, f):
    if path.suffix == '.tsv':
        return pd.read_csv(f, sep='\t', low_memory=False)
    return pd.read_csv(f, low_memory=False)


def main():
    print('Started')
    parser = argparse.ArgumentParser(description="A Script to format csv/tsv files in order to upload to XSIEM. "
                                                 "This script is a work in progress and does not "
                                                 "give a complete solution. if found a dataset that"
                                                 " does not upload after running the script plz DM",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", "--input", help="Input file path")
    parser.add_argument("-o", "--output", help="Output file path. If not specified the "
                                               "file will be saved in the folder the script was executed from")
    parser.add_argument("-v", "--verbose", action='store_true',
                        help="In order to vies the columns modified by the script")

    args = parser.parse_args()
    input_path = Path(args.input)
    last_path_component = input_path.stem
    last_path_component += f'_formatted.csv'
    output_path = Path(input_path.parent, last_path_component)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    format_manager = FormatManager()
    with open(input_path) as f:
        data_table = open_input_file(input_path, f)

    for col in data_table.columns:
        col_values_list = data_table[col].to_list()
        format_manager.find_col_format(col_values_list)
        if format_manager.format_type:
            logging.debug(f'{col} --- was found to be of format: {format_manager.formatter_name()}')
            formatted_col = format_manager.convert_to_xsiem_format(col_values_list)
            data_table[col] = formatted_col

    print(f'saving the formatted csv file to - {output_path}')
    data_table.to_csv(output_path, index=False)


if __name__ == '__main__':
    main()

