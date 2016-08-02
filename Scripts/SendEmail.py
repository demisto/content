from string import Template
body = Template(demisto.args()['body'].replace('\\n', '\n'))
subject = Template(demisto.args()['subject'])
to = demisto.args()['to']
subject = subject.safe_substitute(name=demisto.incidents()[0]['name'])
body = body.safe_substitute(recipient=to)
demisto.results(demisto.executeCommand('send-mail', {'to': to, 'subject': subject , 'body': body}))
