import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import random
current = random.randint(1, 30)
return_results(TrendWidget(current, random.randint(0, current)))
