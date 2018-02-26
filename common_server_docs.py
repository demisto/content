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
        out = yaml.load(f)
        return out
    return []


def reformatPythonOutput(output):
    for a in output:
        args = a.get("arguments", {})
        z = []
        for argName, argInfo in args.iteritems():
            argInfo["name"] = argName
            argInfo["type"] = argInfo["type_name"]
            del argInfo["type_name"]
            z.append(argInfo)
        a["arguments"] = z
        a["return"]["type"] = a["return"]["type_name"]
        del a["return"]["type_name"]
    return output


def main(argv):
    # create commonServer js file to extract doc from
    commonServer = readFile('./Scripts/script-CommonServer.yml')
    jsScript = commonServer.get("script", "")
    with open('commonServerJsDoc.js', 'w') as fp:
        fp.write(jsScript)

    # create commonServerPy json doc
    commonServerPython = readFile('./Scripts/script-CommonServerPython.yml')
    pyScript = commonServerPython.get("script", "")

    code = compile(pyScript, '<string>', 'exec')
    ns = {}
    exec code in ns

    x = []

    for a in ns:
        if callable(ns.get(a)):
            try:
                y = parser.parse_docstring((inspect.getdoc(ns.get(a))))
                y["name"] = a
                x.append(y)
            except:
                print "Bad docstring in function", a

    x = reformatPythonOutput(x)
    with open('commonServerPyDoc.json', 'w') as fp:
        json.dump(x, fp)


if __name__ == "__main__":
    main(sys.argv[1:])
