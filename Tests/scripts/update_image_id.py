import json
import argparse


def main(image_id, confile):
    print("Extracting instance conf file")
    with open(confile, 'r') as conf_file:
        conf = json.load(conf_file)

    print("Getting new image ID")
    with open(image_id, 'r') as image_id_file:
        image_id_lines = image_id_file.readlines()
        image_id_lines = [line.strip('\n') for line in image_id_lines]
        print(image_id_lines)
        id = image_id_lines[0]
        id = id.split()[0]

    conf['ImageId'] = id

    print("Setting new image ID")
    with open(confile, 'w') as conf_file:
        data = json.dumps(conf)
        conf_file.write(data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Utility for updating image id')
    parser.add_argument('-i', '--image', help='The image_id', required=True)
    parser.add_argument('-c', '--conf', help='The conf file', required=True)
    options = parser.parse_args()

    main(options.image, options.conf)
