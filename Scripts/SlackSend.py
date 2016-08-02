dArgs = {}
for argName in ['message', 'to', 'channel', 'group', 'entry']:
    if demisto.get(demisto.args(), argName):
        dArgs[argName] = demisto.args()[argName]

demisto.results( demisto.executeCommand( 'slack-send', dArgs )  )
