import datetime
import re
from CommonServerPython import *

ago = arg_to_datetime('3 days')
print(ago)
d = ago.astimezone().replace(microsecond=0).isoformat()
print(d)
regex = r'(?!.*:)'
r = re.search(regex, d)
index = r.start()
g = d[:index-1] + d[index:]
print(g)
