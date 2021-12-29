"""

"""

# python 3.9 imports
from functools import wraps
from json import dumps, loads, JSONDecodeError
from traceback import format_exc

# accessdata imports
from accessdata.api.agents import Agent
from accessdata.api.jobs import Job
from accessdata.api.filters import and_, or_
from accessdata.client import Client

# xsoar imports
from CommonServerPython import *
import demistomock as demisto

""" decorator wrapping demisto commands """

_run_functions = {}


def wrap_demisto_command(command):
    def _func(func):
        @wraps(func)
        def _inside(*args, **kwargs):
            return func(*args, **kwargs)

        _run_functions[command] = func
        return _inside

    return _func


""" register demisto commands """


@wrap_demisto_command("accessdata-api-get-case-by-name")
def _get_case_by_name(client, name):
    case = client.cases.first_matching_attribute("name", name)
    if not case:
        raise ValueError(f"Failed to gather case with name ({name}).")

    return CommandResults(
        outputs_prefix="Accessdata.Case",
        outputs={
            "ID": case["id"],
            "Name": name,
            "CaseFolder": case["ftkcasefolderpath"]
        },
        outputs_key_field="ID",
        readable_output=tableToMarkdown("Case", dict(case))
    )


@wrap_demisto_command("accessdata-api-create-case")
def _create_case(client, **kwargs):
    case = client.cases.create(**kwargs)
    if not case:
        raise ValueError("Failed to create case.")

    return CommandResults(
        outputs_prefix="Accessdata.Case",
        outputs={
            "ID": case["id"],
            "Name": case["name"],
            "CaseFolder": case["ftkcasefolderpath"]
        },
        outputs_key_field="ID",
        readable_output=tableToMarkdown("Case", dict(case))
    )


@wrap_demisto_command("accessdata-api-process-evidence")
def _process_evidence(client, caseid, evidence_path, evidence_type, options):
    # gather the case object from it's id
    case = client.cases.first_matching_attribute("id", int(caseid))
    if not case:
        raise ValueError(f"Failed to gather case with id ({caseid}).")

    # try find json in the options
    try:
        options = loads(options)
    except Exception:
        pass

    # determine the type of processing options supplied
    options_type = type(options)
    if options_type is str:
        jobs = case.evidence.process(evidence_path, evidence_type,
                                     completeprocessingoptions=options)
        return CommandResults(
            outputs_prefix="Accessdata.Case.Job",
            outputs={"ID": jobs[0]["id"]},
            outputs_key_field="ID",
            readable_output=tableToMarkdown("Job", dict(jobs[0]))
        )
    elif options_type is dict:
        jobs = case.evidence.process(evidence_path, evidence_type,
                                     processingoptions=options)
        return CommandResults(
            outputs_prefix="Accessdata.Case.Job",
            outputs={"ID": jobs[0]["id"]},
            outputs_key_field="ID",
            readable_output=tableToMarkdown("Job", dict(jobs[0]))
        )
    # if bad, raise error
    else:
        raise ValueError("Processing Options supplied are not supported. Must be `dict` or `string`.")


@wrap_demisto_command("accessdata-api-export-natives")
def _export_natives(client, caseid, path, filter_json):
    # gather the case object from it's id
    case = client.cases.first_matching_attribute("id", caseid)
    if not case:
        raise ValueError(f"Failed to gather case with id ({caseid}).")

    job = case.evidence.export_natives(path, filter=filter_json)
    return CommandResults(
        outputs_prefix="Accessdata.Case.Job",
        outputs={
            "ID": job["id"],
        },
        outputs_key_field="ID",
        readable_output=tableToMarkdown("Job", dict(job))
    )


@wrap_demisto_command("accessdata-api-label-search-term")
def _label_search_term(client, caseid, keyword, filter_json):
    # gather the case object from it's id
    case = client.cases.first_matching_attribute("id", caseid)
    if not case:
        raise ValueError(f"Failed to gather case with id ({caseid}).")

    case.evidence.search_keyword([keyword], filter=loads(filter_json))
    return CommandResults(
        outputs_prefix="Accessdata.Case.Label",
        outputs={
            "Name": keyword
        },
        outputs_key_field="Name",
        readable_output=tableToMarkdown("Accessdata.Case.Label", {
            "Name": keyword
        })
    )


@wrap_demisto_command("accessdata-api-get-job-status")
def _get_job_status(client, caseid, jobid):
    # gather the case object from it's id
    case = client.cases.first_matching_attribute("id", int(caseid))
    if not case:
        raise ValueError(f"Failed to gather case with id ({caseid}).")

    job = Job(case, id=int(jobid))
    if not job:
        raise ValueError(f"Failed to gather job with id ({jobid}).")

    job.update()
    return CommandResults(
        outputs_prefix="Accessdata.Case.Job",
        outputs={
            "ID": job["id"],
            "State": str(job["state"]),
            "ResultData": dumps(job["resultData"])
        },
        outputs_key_field="ID",
        readable_output=tableToMarkdown("Job", dict(job))
    )


@wrap_demisto_command("accessdata-api-endpoint-volatile-analysis")
def _run_volatile_analysis(client, caseid, target):
    # gather the case object from it's id
    case = client.cases.first_matching_attribute("id", int(caseid))
    if not case:
        raise ValueError(f"Failed to gather case with id ({caseid}).")

    agent = Agent(case, target)
    job = agent.analyse_volatile()

    return CommandResults(
        outputs_prefix="Accessdata.Case.Job",
        outputs={
            "ID": job["id"],
        },
        outputs_key_field="ID",
        readable_output=tableToMarkdown("Job", dict(job))
    )


@wrap_demisto_command("accessdata-api-endpoint-memory-collect")
def _run_memory_acquisition(client, caseid, target):
    # gather the case object from it's id
    case = client.cases.first_matching_attribute("id", int(caseid))
    if not case:
        raise ValueError(f"Failed to gather case with id ({caseid}).")

    agent = Agent(case, target)
    job = agent.acquire_memory()

    return CommandResults(
        outputs_prefix="Accessdata.Case.Job",
        outputs={
            "ID": job["id"],
        },
        outputs_key_field="ID",
        readable_output=tableToMarkdown("Job", dict(job))
    )


@wrap_demisto_command("accessdata-api-endpoint-disk-collect")
def _run_disk_acquisition(client, caseid, target, **kwargs):
    # gather the case object from it's id
    case = client.cases.first_matching_attribute("id", int(caseid))
    if not case:
        raise ValueError(f"Failed to gather case with id ({caseid}).")

    agent = Agent(case, target)
    job = agent.acquire_disk(**kwargs)

    return CommandResults(
        outputs_prefix="Accessdata.Case.Job",
        outputs={
            "ID": job["id"],
        },
        outputs_key_field="ID",
        readable_output=tableToMarkdown("Job", dict(job))
    )


_comparator_mapping = {
    "==": "__eq__",
    "!=": "__ne__",
    ">": "__gt__",
    "<": "__lt__",
    ">=": "__ge__",
    "<=": "__le__"
}


@wrap_demisto_command("accessdata-api-create-filter")
def _create_filter(client, column, comparator, value):
    comp = _comparator_mapping.get(comparator, comparator)
    # get the relevant attribute
    attr = client.attributes.first_matching_attribute("attributeUniqueName", column)
    # if not exists, raise error
    if not attr:
        raise ValueError(f"Cannot find attribute of name ({column}).")
    # try get comparison method
    has_comp = hasattr(attr, comp)
    if not has_comp:
        raise ValueError(f"Cannot find compare method of method name ({comp}).")
    # compare and return
    filter_json = getattr(attr, comp)(value)
    return CommandResults(
        outputs_prefix="Accessdata",
        outputs={
            "Filter": dumps(filter_json)
        },
        outputs_key_field="Filter",
        readable_output=tableToMarkdown("Filter", filter_json)
    )


@wrap_demisto_command("accessdata-api-combine-filter-and")
def _and_filter(client, filter_json1, filter_json2):
    # try find json in the filters
    try:
        filter_json1 = loads(filter_json1)
        filter_json2 = loads(filter_json2)
    except JSONDecodeError:
        raise ValueError("Both filters must be JSON content.")

    filter_json = and_(filter_json1, filter_json2)
    return CommandResults(
        outputs_prefix="Accessdata",
        outputs={
            "Filter": dumps(filter_json)
        },
        outputs_key_field="Filter",
        readable_output=tableToMarkdown("Filter", filter_json)
    )


@wrap_demisto_command("accessdata-api-combine-filter-or")
def _or_filter(client, filter_json1, filter_json2):
    # try find json in the filters
    try:
        filter_json1 = loads(filter_json1)
        filter_json2 = loads(filter_json2)
    except JSONDecodeError:
        raise ValueError("Both filters must be JSON content.")

    filter_json = or_(filter_json1, filter_json2)
    return CommandResults(
        outputs_prefix="Accessdata",
        outputs={
            "Filter": dumps(filter_json)
        },
        outputs_key_field="Filter",
        readable_output=tableToMarkdown("Filter", filter_json)
    )


@wrap_demisto_command("test-module")
def _test_module(client):
    # test the client can reach the case list
    try:
        client.cases
    except DemistoException as exc:
        raise RuntimeError(str(exc))

    return "ok"


""" define entry """  #


def main():
    # gather parameters
    params = demisto.params()

    # generate client arguments
    protocol = params.get("PROTOCOL", "http")
    port = params.get("PORT", "4443")
    address = params.get("SERVER", "localhost")
    url = f"{protocol}://{address}:{port}/"
    apikey = params.get("APIKEY", "")
    # check if using ssl
    is_secure = protocol[-1] == 's'

    # build client
    client = Client(url, apikey, validate=not is_secure)
    # if using ssl, gather certs and apply
    if is_secure:
        public_certificate = params.get("PUBLIC_CERT", None)
        client.session.cert = public_certificate

    try:
        # call function with supplied args
        command = demisto.command()
        func = _run_functions[command]
        args = demisto.args()

        # return value from called function
        return_values = func(client, **args)
        return_results(return_values)
    except Exception as exception:
        demisto.error(format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(exception)}')


""" Entry Point """

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
