# Find the recipient of the email - should be the target
target = ''
for t in demisto.incidents()[0]['labels']:
    if t['type'] == 'Email/from':
        target = t['value']
        break

if target == '':
    for t in demisto.incidents()[0]['labels']:
        if t['type'] == 'Email':
            target = t['value']
            break

if target == '':
    demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'], 'Contents': 'Could not find the target email'})
else:
    from string import Template
    import textwrap
    defaultBody = """\
        Hi $target,
        We've concluded that the email you forwarded to us is malicious. We've taken steps to blacklist the sender and quarantine the email.
        Good job on detecting and forwarding it to us!

        Cheers,
        Your friendly security team"""
    body = demisto.args()['body'] if demisto.get(demisto.args(), 'body') else defaultBody
    actualBody = Template(body)
    subject = demisto.args()['subject'] if demisto.get(demisto.args(), 'subject') else 'Security Email Re Malicious: ' + demisto.incidents()[0]['name']
    demisto.results(demisto.executeCommand('send-mail', {'to': target, 'subject': subject, 'body': textwrap.dedent(actualBody.safe_substitute(target=target))}))
