import sys
import json

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
        y["origin"] = "CommonServer"
        for arg in a.get("params", {}):
            arg["type"] = " or ".join(arg.get("type", {}).get("names", []))
        y["arguments"] = a.get("params", {})

        x.append(y)


    with open('doc-CommonServer.json', 'r+') as fp:
        res = json.load(fp)
        res.append(x)
        fp.seek(0)
        json.dump(res, fp)

if __name__ == "__main__":
   main(sys.argv[1:])
