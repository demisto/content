import json
import sys


def main():
    if len(sys.argv) < 2:
        raise FileNotFoundError("No File Path Given")

    file_path = sys.argv[1]
    field = sys.argv[2]

    with open(file_path, 'r') as f:
        file_content = json.load(f)

    file_content[field] = f"{file_content['id']}-new"

    with open(file_path, 'w') as f:
        json.dump(file_content, f)

    print(f"Successfully changed the field {field} in file {file_path}")


if __name__ == '__main__':
    main()
