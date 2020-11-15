import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

step = demisto.args()['step']
answer = demisto.args()['answer']

step_to_answer = {
    '1': 'answer1',
    '2': 'answer2'
}

# if task == '14':

if step_to_answer[step] == answer:
    demisto.results('correct, next hint')
else:
    raise Exception('wrong')
