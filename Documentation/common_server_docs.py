import inspect
import json
import sys
import yaml
import os
import re
from parinx import parser
import logging

from Tests.scripts.utils.log_util import install_logging

# temp handling of unifier import
try:
    from demisto_sdk.commands.unify.integration_script_unifier import IntegrationScriptUnifier as YmlUnifier
except:  # noqa
    from demisto_sdk.commands.prepare_content.integration_script_unifier import IntegrationScriptUnifier as YmlUnifier

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONTENT_DIR = os.path.abspath(SCRIPT_DIR + '/..')
sys.path.append(CONTENT_DIR + '/Tests/demistomock')
import demistomock  # noqa: E402

# PrivateFuncs are functions to ignore when running the script
JS_PRIVATE_FUNCS = ["dqQueryBuilder", "toArray", "indent", "formatTableValuesRecursive", "string_to_array",
                    "array_to_hex_string", "SHA256_init", "SHA256_write", "SHA256_finalize", "SHA256_hash",
                    "HMAC_SHA256_init", "HMAC_SHA256_write", "HMAC_SHA256_finalize", "HMAC_SHA256_MAC"]

PY_PRIVATE_FUNCS = ["raiseTable", "zoomField", "epochToTimestamp", "formatTimeColumns", "strip_tag", "elem_to_internal",
                    "internal_to_elem", "json2elem", "elem2json", "json2xml", "OrderedDict", "datetime", "timedelta",
                    "createContextSingle", "IntegrationLogger", "tblToMd", "DemistoException",
                    "BaseHTTPClient", "DemistoHandler", "DebugLogger", "FeedIndicatorType", "Indicator",
                    "IndicatorType", "EntryType", "EntryFormat", "abstractmethod",
                    "HTTPAdapter", "Retry", "Common", "randint", "GetDemistoVersion", "get_demisto_version",
                    "BaseWidget", "UTC", "WarningsHandler", "__line__", "_find_relevant_module", "register_module_line",
                    "fix_traceback_line_numbers"]

PY_IRREGULAR_FUNCS = {"LOG": {"argList": ["message"]}}

JS_AUTOMATION_ONLY = ["fileNameFromEntry", "closeInvestigation", "setSeverity", "setIncident", "createNewIncident",
                      "setPlaybookAccordingToType", "setOwner", "taskAssign", "setTaskDueDate", "setPlaybook",
                      "addTask",
                      "getCSVListAsArray", "getJSONListAsObject"]

MARKDOWN_DESCRIPTION_FUNCS = ["createEntry"]


def read_json_file(file_path):
    with open(file_path) as f:
        out = json.load(f)
        return out


def read_yml_file(filepath):
    with open(filepath) as f:
        out = yaml.safe_load(f)
        return out


def reformat_python_output(output, origin, language):
    res = []
    is_error = False
    for a in output:
        if "deprecated" in a["description"]:
            continue

        if a.get("description", "") == "":
            logging.error("Description is missing for Python function %s", a["name"])
            is_error = True

        # format arguments
        z = []
        arg_list = a.get("argList", [])
        arg_details = a.get("arguments", {})
        for arg_name in arg_list:
            arg_info = arg_details.get(arg_name, None)
            if arg_info is not None:
                arg_info["name"] = arg_name
                arg_info["type"] = arg_info["type_name"]
                if arg_info.get("description", "") == "":
                    is_error = True
                    logging.info("Missing description for argument %s in python function %s", arg_name, a["name"])
                del arg_info["type_name"]
                z.append(arg_info)

        a["arguments"] = z
        a["return_value"] = a["return"]
        a["return_value"]["type"] = a["return_value"]["type_name"]
        if a["name"] in MARKDOWN_DESCRIPTION_FUNCS:
            a["markdown"] = True
        a["language"] = language
        a["origin"] = origin

        del a["argList"]
        del a["return"]
        del a["return_value"]["type_name"]
        res.append(a)

    return res, is_error


def create_js_documentation(path, origin, language):
    is_error = False
    common_server_js = read_json_file(path)
    x = []
    for a in common_server_js:
        if (a.get("deprecated", None) is not None) or a.get("name", "") in JS_PRIVATE_FUNCS:
            continue

        y = {}
        y["name"] = a.get("name", "")
        if y["name"] == "":
            logging.error("Error extracting function name for JS function with the following data:\n%s", a)
            is_error = True
        y["description"] = a.get("description", "")
        if y["description"] == "":
            logging.error("Description is missing for JS function %s", y["name"])
            is_error = True

        for arg in a.get("params", []):
            arg["type"] = " or ".join(arg.get("type", {}).get("names", []))
            arg["required"] = True
            if arg.get("optional"):
                arg["required"] = False
                del arg["optional"]
            if arg.get("name", "") == "" or arg.get("description", "") == "":
                is_error = True
                logging.error("Missing name/description for argument in JS function %s.\nArg name is %s, args description is %s",
                              y["name"], arg.get("name", ""), arg.get("description", ""))
        y["arguments"] = a.get("params", [])

        returns = a.get("returns", None)[0]
        y["return_value"] = {"description": returns.get("description"),
                             "type": " or ".join(returns.get("type", {}).get("names", []))}
        if y["name"] in MARKDOWN_DESCRIPTION_FUNCS:
            y["markdown"] = True
        y["language"] = language
        y["origin"] = origin
        if y["name"] in JS_AUTOMATION_ONLY:
            y["automationOnly"] = True

        x.append(y)
    return x, is_error


def create_py_documentation(path, origin, language):
    is_error_py = False

    with open(path) as file:
        py_script = YmlUnifier.clean_python_code(file.read(), remove_print_future=False)

    logging.info("replacing DemistoClassApiModule: ")
    py_script = re.sub(r'from DemistoClassApiModule import \*[ \t]*(#.*)?', "", py_script)

    code = compile(py_script, '<string>', 'exec')
    ns = {'demisto': demistomock}
    exec(code, ns)  # guardrails-disable-line # pylint: disable=W0122

    x: list = []

    for a in ns:
        a_object = ns.get(a)
        if a != 'demisto' and callable(a_object) and a not in PY_PRIVATE_FUNCS and ns \
                and a_object.__module__ in (None, 'builtin', 'builtins'):

            docstring = inspect.getdoc(a_object)
            if not docstring:
                logging.error(f"docstring for function {a} is empty")
                is_error_py = True
            elif 'ignore docstring' in docstring:
                continue
            else:
                try:
                    y = parser.parse_docstring(docstring)
                    y["name"] = a
                    logging.info(f'Processing {a}')

                    if inspect.isclass(a_object):
                        y["argList"] = list(inspect.getfullargspec(a_object.__init__))[0] \
                            if PY_IRREGULAR_FUNCS.get(a, None) is None \
                            else PY_IRREGULAR_FUNCS[a]["argList"]

                        # init will contains self, so remove the self from the arg list
                        y["argList"].remove('self')
                    else:
                        y["argList"] = list(inspect.getfullargspec(a_object))[0] \
                            if PY_IRREGULAR_FUNCS.get(a, None) is None \
                            else PY_IRREGULAR_FUNCS[a]["argList"]

                    x.append(y)
                except parser.MethodParsingException:
                    logging.exception(f'Failed to parse {a} class/function')
                    is_error_py = True

    if is_error_py:
        return None, is_error_py
    return reformat_python_output(x, origin, language)


def create_ps_documentation(path, origin, language):
    is_error_ps = False

    with open(path) as file:
        ps_script = file.read()

    function_doc_list = []
    functions_list = re.findall(r'function\s([\w_]*)\s{\s*<#\s*(.*?)#>', ps_script, re.S)

    for function in functions_list:

        function_doc = {
            'language': language,
            'origin': origin
        }
        function_name = function[0]
        function_doc['name'] = function_name
        parameters = function[1].split('.PARAMETER')

        description = parameters[0].split('.DESCRIPTION')[1].strip()
        if not description:
            is_error_ps = True
            logging.error(f"Missing description for PS function {function_name}.\n")
        function_doc['description'] = description

        arguments = []

        for parameter in parameters[1:]:

            split_param: list = list(filter(None, parameter.split('\n')))
            required = False
            param_name = split_param[0].strip()
            if 'required' in param_name:
                required = True
                param_name = param_name.replace(' (required)', '')
            param_description = split_param[1]
            if not param_description:
                is_error_ps = True
                logging.error("Missing parameter description for parameter {} for in PS function {}.\n".format(
                    param_name, function_name))
            arguments.append({
                'name': param_name,
                'description': param_description,
                'required': required
            })

        function_doc['arguments'] = arguments
        function_doc_list.append(function_doc)

    return function_doc_list, is_error_ps


def main():
    install_logging('Common Server Documentation.log')
    js_doc, is_error_js = create_js_documentation('./Documentation/commonServerJsDoc.json', 'CommonServerJs',
                                                  'javascript')
    py_doc, is_error_py = create_py_documentation('./Packs/Base/Scripts/CommonServerPython/CommonServerPython.py',
                                                  'CommonServerPython', 'python')
    ps_doc, is_error_ps = create_ps_documentation(
        './Packs/Base/Scripts/CommonServerPowerShell/CommonServerPowerShell.ps1',
        'CommonServerPowerShell', 'powershell')
    final_docs = read_json_file('./Documentation/commonServerConstants.json')

    if is_error_js or is_error_py or is_error_ps or not final_docs:
        logging.critical("Errors found in common server docs.")
        sys.exit(1)
    with open('./Documentation/doc-CommonServer.json', 'w') as fp:
        final_docs += py_doc
        json.dump(final_docs, fp)


if __name__ == "__main__":
    main()
