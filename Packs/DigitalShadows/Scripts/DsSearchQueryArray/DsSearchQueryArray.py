import re
import traceback
from typing import Any, Dict

options = ["IP.Address", "Domain.Name", "URL.Data", "File.MD5", "File.SHA256", "File.SHA1", "CVE.ID"]

QUOTED_STRINGS_PATTERN = r'\"[^\"]*\"'
KEYWORDS_PATTERN = " (AND|OR|NOT) "
NON_WORD_PATTERN = "\W+"


def convert_to_ds_query_array(args: Dict[str, Any]):

    if len(args["field"].split(".")) != 2:
        raise Exception("Invalid field argument, make sure it follows the format \"Field.Property\"")

    if args['field'] not in options:
        raise Exception(f"{args['field']} is not a valid field")

    field_type = args["field"].split(".")[0]
    field_type_property = args["field"].split(".")[1]

    data = args["value"][field_type]

    def extractData(query_field):
        return query_field[field_type_property]

    if (isinstance(data, list)):
        res = list()
        query = [extractData(query_field) for query_field in data]
        query = sorted(query, key=lambda x: count_terms(x))
        init = list()
        term_count = 0

        for idx in range(len(query)):
            if (term_count + count_terms(query[idx]) > 35):
                res.append(" OR ".join(init))
                init = [query[idx]]
                term_count = count_terms(query[idx])
            elif not reject(field_type, query[idx]):
                init.append(query[idx])
                term_count += count_terms(query[idx])
        res.append(" OR ".join(init))
    else:
        if not reject(field_type, data[field_type_property]):
            return data[field_type_property]
        return ""

    return res


def reject(field, string):
    return {
        "IP": lambda x: "0.0.0.0" in x,
        "Domain": lambda x: "portal-digitalshadows.com" in x,
        "URL": lambda x: "portal-digitalshadows.com" in x,
        "File": lambda x: False,
        "CVE": lambda x: False
    }[field](string)


def count_terms(query):
    query = re.sub(QUOTED_STRINGS_PATTERN, "x", query)
    query = re.sub(KEYWORDS_PATTERN, " ", query)
    query = re.sub(NON_WORD_PATTERN, " ", query)
    query = query.strip()
    term_count = 0
    if (len(query) > 0):
        term_count = query.count(" ") + 1
    return term_count


def main():
    try:
        return_results(convert_to_ds_query_array(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
