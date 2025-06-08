import sys


def readFile(filepath):
    with open(filepath, mode="r") as f:  # noqa: UP015
        out = f.read()
        return out
    return []


def main(argv):
    # create commonServer js file to extract doc from
    jsScript = readFile("./Packs/Base/Scripts/CommonServer/CommonServer.js")
    with open("./Documentation/commonServerJsDoc.js", "w") as fp:
        fp.write(jsScript)


if __name__ == "__main__":
    main(sys.argv[1:])
