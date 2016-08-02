# Optional arguments and default values
attrs = 'name'
if demisto.get(demisto.args(), 'attributes'):
    attrs += "," + demisto.args()['attributes']

filterstr = r"(&(objectCategory=Computer)(memberof=" + demisto.args()['groupdn'] + "))"
demisto.results( demisto.executeCommand( 'ad-search', { 'filter' : filterstr, 'attributes' : attrs } ) )
