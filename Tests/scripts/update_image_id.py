import sys
import json


def main(image_id, confile):
    with open(confile, 'r') as conf_file:
        conf = json.load(conf_file)

    print(image_id)
    conf['ImageId'] = image_id

    with open(confile, 'w') as conf_file:
        data = json.dumps(conf)
        conf_file.write(data)

    print(data)
    sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
