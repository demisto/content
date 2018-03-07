import sys
import json

contentLibPath = "./"
limitedVersion = False
privateFuncs = ["dqQueryBuilder", "toArray", "indent", "formatTableValuesRecursive", "string_to_array", "array_to_hex_string",
                "SHA256_init", "SHA256_write", "SHA256_finalize", "SHA256_hash", "HMAC_SHA256_init", "HMAC_SHA256_write",
                "HMAC_SHA256_finalize", "HMAC_SHA256_MAC"]

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
        if (a.get("deprecated", None) is not None) or a.get("name", "") in privateFuncs:
            continue
        y = {}
        y["name"] = a.get("name", "")
        y["description"] = a.get("description", "")
        returns = a.get("returns", None)[0]
        y["return_value"] = {"description" : returns.get("description"), "type":  " or ".join(returns.get("type", {}).get("names", []) ) }
        y["language"] = "javascript"
        y["origin"] = "CommonServerJs"
        for arg in a.get("params", {}):
            arg["type"] = " or ".join(arg.get("type", {}).get("names", []))
            arg["required"] = True
            if arg.get("optional"):
                arg["required"] = False
                del arg["optional"]
        y["arguments"] = a.get("params", [])

        x.append(y)

    with open('doc-CommonServer.json', 'r+') as fp:
        res = json.load(fp)
        res += x
        fp.seek(0)
        json.dump(res, fp)

if __name__ == "__main__":
   main(sys.argv[1:])
