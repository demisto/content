import demistomock as demisto
from CommonServerPython import *
args = demisto.args()

# Get the input value
value = args.get('value')

# Get the input array (CSV)
input_values = args.get('input_values', []).split(",")

# Get the mapped array (CSV)
mapped_values = args.get('mapped_values', []).split(",")

# Convert the input value to a string
value = str(value)

# Convert the array items to strings
input_values[:] = [str(x) for x in input_values]
mapped_values[:] = [str(x) for x in mapped_values]

# If the length of the arrays are not equal, return an error
if len(input_values) != len(mapped_values):
    return_error('Length of input_values and mapped_values are not the same')

# Create the dictionary of input and mapped values
mapper = dict()
for index in range(0, len(input_values)):
    mapper[input_values[index]] = mapped_values[index]

# If the value exists in the dictionary, return its value
if value in mapper:
    demisto.results(mapper[value])

# Otherwise return the original value
else:
    demisto.results(value)
