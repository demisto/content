import sys
import yaml


def readFile(filepath):
    with open(filepath, 'r') as f:
        out = yaml.load(f)
        return out
    return []


def main(argv):
    # create commonServer js file to extract doc from
    commonServer = readFile('./Scripts/script-CommonServer.yml')
    jsScript = commonServer.get("script", "")
    with open('./Documentation/commonServerJsDoc.js', 'w') as fp:
        fp.write(jsScript)


if __name__ == "__main__":
    main(sys.argv[1:])
