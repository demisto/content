import argparse
import os


def search_string_in_files(folder_path, search_string):
    # Iterate through all files in the folder and its subfolders
    failed = []
    search_string = [s.replace(' (Second Playback)', '').replace('%', '') for s in search_string]
    for root, dirs, files in os.walk(folder_path):
        if 'Bitbucket' in root:
            print(5)
        if root.split('/')[-1] != 'TestPlaybooks':
            continue
        for file_name in files:
            file_path = os.path.join(root, file_name)
            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    content = file.read()
                    for s in search_string:
                        print(f"searching '{s}' in '{file_path}'")
                        if s in content:
                            print(f"Found '{s}' in '{file_path}'")
                            failed.append(f'{file_path.split("/Packs/")[1].split("/")[0]}/{s}')
            except Exception as e:
                print(f"Error reading '{file_path}': {e}")
    return failed


def run(options: argparse.Namespace):
    folder_path = options.folder
    failed_tests_path = f'{folder_path}/failed_tests.txt'
    # failed_tests_path = f'/Users/gforer/Downloads/artifacts16666/artifacts/xsoar/failed_tests.txt'
    packs_folder = './Packs'
    with open(failed_tests_path) as file:
        failed_tests = file.read().splitlines()
    print(f'^^^^{failed_tests=}^^^^')
    failed = search_string_in_files(packs_folder, failed_tests)
    print(f'{failed=}')
    if failed:
        print(f'{",".join(failed)}')
        with open(f'{folder_path}/failed_tests_path.txt', 'w') as secrets_out_file:
            try:
                secrets_out_file.write(",".join(failed))
            except Exception as e:
                print(f'Could not save secrets file, malformed json5 format, the error is: {e}')


def options_handler(args=None) -> argparse.Namespace:
    """
    Parse  the passed parameters for the script
    :param args: a list of arguments to add
    :return: the parsed arguments that were passed to the script
    """
    parser = argparse.ArgumentParser(description='Utility for Importing secrets from Google Secret Manager.')
    parser.add_argument('-f', '--folder', help='The folder.')
    options = parser.parse_args(args)

    return options


if __name__ == '__main__':
    options = options_handler()
    run(options)
