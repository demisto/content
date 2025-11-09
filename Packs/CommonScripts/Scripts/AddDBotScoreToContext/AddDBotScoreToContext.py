from time import sleep
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    indicator=demisto.args().get("indicator")
    indicatorType=demisto.args().get("indicatorType")
    SCORE = int( demisto.args().get("score") )
    vendor=demisto.args().get(  "vendor")
    Reliability=demisto.args().get("reliability",None)
    LOG(   "Got all arguments" )

    dbotscore={"Indicator":indicator,"Type":indicatorType,"Vendor":vendor,"Score":SCORE,"Reliability":Reliability}

    command_results=CommandResults(outputs_prefix = "DBotScore" , outputs = dbotscore)
    sleep(10000000)
    return_results(  command_results   )

if __name__ == "__builtin__" or __name__ == "builtins":
    main()
