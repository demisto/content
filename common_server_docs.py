import abc
import datetime
import json
import sys
import yaml
from parinx import parser
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
                x.append(y)
                print "i"
            except:
                print "Bad docstring in function", a

    x = reformatPythonOutput(x)
    with open('commonServerPyDoc.json', 'w') as fp:
        json.dump(x, fp)



if __name__ == "__main__":
   main(sys.argv[1:])
