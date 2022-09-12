import demistomock as demisto

def main():
    inc = demisto.incidents()[0]['CustomFields']
    email_topics = []
    if "emailtopicslist" in inc:
        email_topics = inc.get('emailtopicslist')

    # Add topic to select options of emailtopics field
    demisto.results({'hidden': False, 'options': email_topics})
    return email_topics

if __name__ in ("__main__","__builtin__","builtins"):
    main()
