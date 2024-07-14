import traceback


""" STANDALONE FUNCTION """


def update_context(fields: dict, context: dict) -> None:
    outputs = {}
    for field_name, default_values in fields.items():
        if not context.get(field_name):
            outputs[field_name] = default_values

    demisto.executeCommand("setIncident", outputs)


""" MAIN FUNCTION """


def main():
    try:
        context = demisto.incident()
        args = demisto.args()
        field_name = args.get("field_name")
        value = args.get("value")
        fields_to_update = {field_name: value}
        return_results(update_context(fields_to_update, context))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute BaseScript. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
