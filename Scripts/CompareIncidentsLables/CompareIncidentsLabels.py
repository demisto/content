import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
try:
    inc1=demisto.args().get('inc1')
    inc2=demisto.args().get('inc2')
    inc1_data = demisto.executeCommand("getIncidents", {'id':inc1})[0].get('Contents').get('data')
    inc2_data = demisto.executeCommand("getIncidents", {'id':inc2})[0].get('Contents').get('data')
    if inc1_data is None or inc2_data is None:
        return_error("One of the incidents does not exist.")

    inc1_labels=inc1_data[0].get('labels')
    inc2_labels=inc2_data[0].get('labels')
    in1not2=[]
    in2not1=[]
    for label in inc1_labels:
        if label not in inc2_labels:
            in1not2.append(label)
    for label in inc2_labels:
        if label not in inc1_labels:
            in2not1.append(label)

    md = tableToMarkdown("Labels in issue {} but not in issue {}".format(inc1,inc2), in1not2)
    md= md+"\n"+tableToMarkdown("Labels in issue {1} but not in issue {0}".format(inc1,inc2), in2not1)

    if in2not1==[] and in1not2==[]:
        md="No different labels."
    return_outputs(md,{})
except Exception as ex:
    demisto.results("An Error has occurred.")
