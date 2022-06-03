from __future__ import print_function
import sys
from pathlib import Path
import re


def add_descriptions(file_path, error_type):

    with open(file_path, 'r') as f:
        error_log = f.read()

    infected_files_ls = extract_errors_list(error_log, error_type)

    for infected_file in infected_files_ls:
        infected_file_path = f'Packs/{infected_file.get("pack_name")}/.pack-ignore'

        with open(infected_file_path, 'r') as f:
            infected_file_text = f.read()

        file_name = f'[file:{infected_file.get("file_name")}]'

        if file_name in infected_file_text:
            updated_infected_file_text = add_error_to_existing_ignore_list(file_name, error_type, infected_file_path)
        else:
            updated_infected_file_text = add_error_to_none_existing_ignore_list(file_name, error_type, infected_file_text)

        with open(infected_file_path, 'w') as f:
            f.write(updated_infected_file_text)


def add_error_to_none_existing_ignore_list(file_name, error_type, txt):
    ignored_file = f'{file_name}\nignore={error_type}\n'
    if txt:
        txt += "\n\n" + ignored_file
    else:
        txt = ignored_file
    return txt


def add_error_to_existing_ignore_list(file_name, error_type, infected_file_path):
    txt = ""
    myfile = open(infected_file_path, "r")
    for line in myfile:
        txt += line
        if txt.endswith(f'{file_name}\n'):
            txt += myfile.readline()
            txt = txt[:-1] + f',{error_type}' + "\n"
    myfile.close()
    return txt


def extract_errors_list(errors_log, error_type):
    errors_ls = []
    infected_paths = re.findall(fr'\nPacks\/(.+)\s-\s\[{error_type}]\\', errors_log)
    for path in infected_paths:
        file_path = Path(path)
        parts = file_path.parts
        errors_ls.append({'pack_name': parts[0], 'file_name': parts[-1]})
    return errors_ls


def main(argv):
    if len(argv) < 2:
        print("Please provide <source errors list>, <requested error>")
        sys.exit(1)

    source_path = argv[0]
    error_type = argv[1]

    print("Starting...")

    add_descriptions(source_path, error_type)

    print("Finished")


if __name__ == "__main__":
    main(sys.argv[1:])
