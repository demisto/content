import inspect
import json
import sys
import yaml
from parinx import parser

contentLibPath = "./"
limitedVersion = False
privateFuncs = ["raiseTable", "zoomField", "epochToTimestamp", "formatTimeColumns", "strip_tag", "elem_to_internal",
                "internal_to_elem", "json2elem", "elem2json", "json2xml", "OrderedDict", "datetime", "timedelta",
                "createContextSingle"]


def readFile(filepath):
    with open(filepath, 'r') as f:
        out = yaml.load(f)
        return out
    return []

def reformatPythonOutput(output):
    res = []
    for a in output:
        if "deprecated" in a["description"]:
            continue
        args = a.get("arguments", {})
        z = []
        for argName, argInfo in args.iteritems():
            argInfo["name"] = argName
            argInfo["type"] = argInfo["type_name"]
            del argInfo["type_name"]
            z.append(argInfo)
        a["arguments"] = z
        a["language"] = "python"
        a["origin"] = "CommonServerPython"
        a["return_value"] = a["return"]
        a["return_value"]["type"] = a["return_value"]["type_name"]

        del a["return"]
        del a["return_value"]["type_name"]
        res.append(a)
    return res


def main(argv):
    # create commonServer js file to extract doc from
    commonServer = readFile('./Scripts/script-CommonServer.yml')
    jsScript = commonServer.get("script", "")
    with open('./Docs/commonServerJsDoc.js', 'w') as fp:
        fp.write(jsScript)

    # create commonServerPy json doc
    commonServerPython = readFile('./Scripts/script-CommonServerPython.yml')
    pyScript = commonServerPython.get("script", "")

    code = compile(pyScript, '<string>', 'exec')
    ns = {}
    exec code in ns

    x = []

    for a in ns:
        if callable(ns.get(a)) and a not in privateFuncs:
            y = parser.parse_docstring((inspect.getdoc(ns.get(a))))
            y["name"] = a
            x.append(y)


    x = reformatPythonOutput(x)
    with open('./Docs/doc-CommonServer.json', 'w') as fp:
        json.dump(x, fp)


if __name__ == "__main__":
    main(sys.argv[1:])
