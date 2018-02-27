import abc
import datetime
import json
import sys
import yaml
import inspect
from parinx import parser
import inspect
import json

import types

contentLibPath = "./"
limitedVersion = False

def readFile(filepath):
    with open(filepath, 'r') as f:
        out = json.load(f)
        return out
    return []

def reformatPythonOutput(output):
    return output

def main(argv):
    commonServer = readFile('./commonServerJsDoc.json')
    x = []
    for a in commonServer:
        print a
        y = {}
        y["name"] = a.get("name", "")
        y["description"] = a.get("description", "")
        returns = a.get("returns", {})[0]
        y["return"] = {"description" : returns.get("description"), "type":  " or ".join(returns.get("type", {}).get("names", []) ) }
        y["language"] = "javascript"
        for arg in a.get("params", {}):
            arg["type"] = " or ".join(arg.get("type", {}).get("names", []))
        y["arguments"] = a.get("params", {})

        x.append(y)

    with open('commonServerJsDoc.json', 'w') as fp:
        json.dump(x, fp)


if __name__ == "__main__":
   main(sys.argv[1:])
