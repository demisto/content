import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json


def main():
    try:
        args = demisto.args()
        """
        Creates a new rule in Cortex Platform with defined conditions, scope, and triggers.
        Args:
            client: The Cortex Platform client instance.
            args: Dictionary containing rule configuration parameters including:
                - rule_name: Required name for the new rule
                - description: Optional rule description
                - severity: Required severity for the new rule
                - labels: Optional labels to be assigned to the rule
                - scanner: Required The type of security scanner used to detect findings of this rule IaC/secret
                - category: Required Custom rule IaC/secret category
                - subCategory: Required for IaC scanner only 
                - frameworks: Required rule frameworks configuration parameters name and definition

        Returns:
            CommandResults: Results object containing the created rule information with
            readable output, outputs prefix, and raw response data.

        Raises:
            DemistoException: If rule name is missing.
        """
        rule_name = args.get("rule_name")
        severity = args.get("severity")
        scanner = args.get("scanner")
        category = args.get("category")
        sub_category = args.get("sub_category")
        frameworks = argToList(args.get("frameworks"))

        if not rule_name:
            raise DemistoException("Rule name is required.")

        if not severity:
            raise DemistoException("Severity is required.")

        if not scanner:
            raise DemistoException("Scanner is required.")

        if not category:
            raise DemistoException("Category is required.")

        if scanner == 'IAC' and not sub_category:
            raise DemistoException("Sub Category is required for IaC scanner.")

        if len(frameworks) == 0 :
            raise DemistoException("Frameworks is required.")

        description = args.get("description", "")
        labels = argToList(args.get("labels"))
        payload = {
            "name": rule_name,
            "description": description,
            "severity": severity,
            "labels": labels,
            "scanner": scanner,
            "category": category,
            "frameworks": frameworks,
            "subCategory": sub_category # Might be None
        }

        # Remove any keys where the value is None
        payload = {k: v for k, v in payload.items() if v is not None}

        demisto.info(f"KUKU payload is {payload}.")
        payload = json.dumps(payload)

        res = demisto.executeCommand(
            "core-generic-api-call",
            {
                "path": "/api/webapp/public_api/appsec/v1/rules",
                "method": "POST",
                "data": payload,
                "headers":{"content-type": 'application/json'}
            },
        )

        if is_error(res):
            demisto.info(f"KUKU error is {res}.")
            return_error(res)

        else:
            demisto.info(f"KUKU finish {res}.")
            context = res[0]["EntryContext"]
            demisto.info(f"KUKU 1111111.")
            data = context.get("data")
            demisto.info(f"KUKU 2222222.")
            data = json.loads(data)
            demisto.info(f"KUKU 3333333. {data}")

            return_results(
                CommandResults(
                    outputs_prefix="Appsec.Rule",
                    outputs=data,
                    readable_output=f"Rules {data}",
                    raw_response=data,
                )
            )
    except Exception as ex:
        return_error(f"Failed to execute CreateAppsecRule. Error:\n{str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
