import demistomock as demisto
from CommonServerPython import *
args = demisto.args()
value = args.get('value')
input_values = args.get('input_values', []).split(",")
mapped_values = args.get('mapped_values', []).split(",")

# Convert all to string
value = str(value)
input_values[:] = [str(x) for x in input_values]
mapped_values[:] = [str(x) for x in mapped_values]

if len(input_values) != len(mapped_values):
    return_error('Length of input_values and mapped_values are not the same')

mapper = dict()
for index in range(0, len(input_values)):
    mapper[input_values[index]] = mapped_values[index]

if value in mapper:
    demisto.results(mapper[value])

else:
    demisto.results(value)
