import inspect
import json
import sys
import yaml
from parinx import parser

jsPrivateFuncs = ["dqQueryBuilder", "toArray", "indent", "formatTableValuesRecursive", "string_to_array", "array_to_hex_string",
                "SHA256_init", "SHA256_write", "SHA256_finalize", "SHA256_hash", "HMAC_SHA256_init", "HMAC_SHA256_write",
                "HMAC_SHA256_finalize", "HMAC_SHA256_MAC"]

pyPrivateFuncs = ["raiseTable", "zoomField", "epochToTimestamp", "formatTimeColumns", "strip_tag", "elem_to_internal",
                "internal_to_elem", "json2elem", "elem2json", "json2xml", "OrderedDict", "datetime", "timedelta",
                "createContextSingle"]

def readJsonFile(filepath):
    with open(filepath, 'r') as f:
        out = json.load(f)
        return out
    return []

def readYmlFile(filepath):
    with open(filepath, 'r') as f:
        out = yaml.load(f)
        return out
    return []

def reformatPythonOutput(output):
    return output

def reformatPythonOutput(output, origin, language):

    res = []
    isError = False
    for a in output:
        if "deprecated" in a["description"]:
            continue

        if a.get("description", "") == "":
            print "Description is missing for Python function", a["name"]
            isError = True

        # format arguments
        z = []
        args = a.get("arguments", {})
        for argName, argInfo in args.iteritems():
            argInfo["name"] = argName
            argInfo["type"] = argInfo["type_name"]
            if argInfo.get("description", "") == "":
                isError = True
                print "Missing description for argument", argName, "in python function", a["name"]
            del argInfo["type_name"]
            z.append(argInfo)

        a["arguments"] = z
        a["return_value"] = a["return"]
        a["return_value"]["type"] = a["return_value"]["type_name"]
        a["language"] = language
        a["origin"] = origin

        del a["return"]
        del a["return_value"]["type_name"]
        res.append(a)

    return res, isError

def createJsDocumentation(path, origin, language):

    isError = False
    commonServerJs = readJsonFile(path)
    x = []
    for a in commonServerJs:
        if (a.get("deprecated", None) is not None) or a.get("name", "") in jsPrivateFuncs:
            continue

        y = {}
        y["name"] = a.get("name", "")
        if y["name"] == "":
            print "Error extracting function name for JS fucntion with the following data:\n", a
            isError = True
        y["description"] = a.get("description", "")
        if y["description"] == "":
            print "Description is missing for JS function", y["name"]
            isError = True

        for arg in a.get("params", []):
            arg["type"] = " or ".join(arg.get("type", {}).get("names", []))
            arg["required"] = True
            if arg.get("optional"):
                arg["required"] = False
                del arg["optional"]
            if arg.get("name", "") == "" or arg.get("description", "") == "":
                isError = True
                print "Missing name/description for argument in JS function", y["name"], ".\n Arg name is", \
                    arg.get("name", ""), ", args description is", arg.get("description", "")
        y["arguments"] = a.get("params", [])

        returns = a.get("returns", None)[0]
        y["return_value"] = {"description": returns.get("description"),
                             "type": " or ".join(returns.get("type", {}).get("names", []))}
        y["language"] = language
        y["origin"] = origin

        x.append(y)
        return x, isError

def createPyDocumentation(path, origin, language):

    # create commonServerPy json doc
    commonServerPython = readYmlFile(path)
    pyScript = commonServerPython.get("script", "")

    code = compile(pyScript, '<string>', 'exec')
    ns = {}
    exec code in ns

    x = []

    for a in ns:
        if callable(ns.get(a)) and a not in pyPrivateFuncs:
            y = parser.parse_docstring((inspect.getdoc(ns.get(a))))
            y["name"] = a
            x.append(y)

    return reformatPythonOutput(x, origin, language)

def main(argv):
    jsDoc, isErrorJS = createJsDocumentation('./Docs/commonServerJsDoc.json', 'CommonServerJs', 'javascript')
    pyDoc, isErrorPy = createPyDocumentation('./Scripts/script-CommonServerPython.yml', 'CommonServerPython', 'python')

    if isErrorJS or isErrorPy:
        print "Errors found in common server docs."
        exit(1)
    with open('./Docs/doc-CommonServer.json', 'r+') as fp:
        jsDoc += pyDoc
        json.dump(jsDoc, fp)


if __name__ == "__main__":
   main(sys.argv[1:])
