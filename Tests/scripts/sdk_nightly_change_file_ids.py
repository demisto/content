import json
import sys


def main():
    if len(sys.argv) < 2:
        raise FileNotFoundError("No File Path Given")

    file_path = sys.argv[1]

    with open(file_path, 'r') as f:
        file_content = json.load(f)

    file_content['id'] = f"{file_content['id']}-new"

    with open(file_path, 'w') as f:
        json.dump(file_content, f)
