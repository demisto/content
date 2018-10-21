import sys
import json
import argparse
import subprocess


def main(confile):
    with open(confile, 'r') as conf_file:
        conf = json.load(conf_file)
    print(json.dumps(conf))

    aws = subprocess.Popen(['aws', 'ec2', 'describe-images', '--filters', 'Name=name,Values=Demisto-Circle-CI-Content-Master*',
                            "--query", "'Images[*].[ImageId,CreationDate]'", "--output", "text"], stdout=subprocess.PIPE)
    aws.wait()
    sort = subprocess.Popen(['sort', '-k2', '-r'], stdin=aws.stdout, stdout=subprocess.PIPE)
    sort.wait()
    image_id = subprocess.Popen(['head', '-n', '1'], stdin=sort.stdout, stdout=subprocess.PIPE)
    image_id.wait()

    image_id = image_id.stdout.read()
    image_id = image_id.split()[0]

    print(image_id)
    print(confile)

    conf['ImageId'] = image_id

    with open(confile, 'w') as conf_file:
        data = json.dumps(conf)
        conf_file.write(data)

    print(data)
    sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Utility for updating image id')
    # parser.add_argument('-i', '--image', help='The image_id', required=True)
    parser.add_argument('-c', '--conf', help='The conf file', required=True)
    options = parser.parse_args()

    main(options.conf)
