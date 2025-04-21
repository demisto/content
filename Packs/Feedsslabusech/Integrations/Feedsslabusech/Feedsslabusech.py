from CommonServerPython import *


def main():
    feed_url_to_config = {
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv": {
            "fieldnames": ["firstseenbysource", "value", "port"],
            "indicator_type": FeedIndicatorType.IP,
            "mapping": {"firstseenbysource": "firstseenbysource", "port": "port"},
        },
        "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv": {
            "fieldnames": ["firstseenbysource", "value", "port"],
            "indicator_type": FeedIndicatorType.IP,
            "mapping": {"firstseenbysource": "firstseenbysource", "port": "port"},
        },
        "https://sslbl.abuse.ch/blacklist/sslblacklist.csv": {
            "fieldnames": ["Listingdate", "value", "Listingreason"],
            "indicator_type": "Certificate",
            "mapping": {
                "firstseenbysource": "Listingdate",
                "relationship_entity_b": "Listingreason",
                "Tags": "Listingreason",
            },
            "relationship_entity_b_type": FeedIndicatorType.Malware,
            "relationship_name": EntityRelationship.Relationships.INDICATOR_OF,
            "auto_detect_type": False,
        },
    }

    params = {k: v for k, v in demisto.params().items() if v is not None}
    params["feed_url_to_config"] = feed_url_to_config
    params["ignore_regex"] = r"^#"
    params["delimiter"] = ","
    params["create_relationships"] = True

    # Main execution of the CSV API Module.
    # This function allows to add to or override this execution.
    feed_main("SSL Blacklist Feed", params, "sslbl")


from CSVFeedApiModule import *  # noqa: E402

if __name__ == "__builtin__" or __name__ == "builtins":
    main()
