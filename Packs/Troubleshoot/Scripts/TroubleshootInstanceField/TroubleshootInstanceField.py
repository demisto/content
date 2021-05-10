from CommonServerPython import *

commands = demisto.getAllSupportedCommands()

options = list(commands.keys())
demisto.results({"hidden": False, "options": options})
