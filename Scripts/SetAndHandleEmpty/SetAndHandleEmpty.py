def main():
    args = demisto.args()
    value = args.get('value')
    #res = {}
    if value:
        human_readable = 'Key ' + args.get('key') + ' set'
        context_entry = {args.get('key'): value}
    else:
        context_entry = {}
        human_readable = 'value is None'
    return_outputs(human_readable, context_entry)
main()