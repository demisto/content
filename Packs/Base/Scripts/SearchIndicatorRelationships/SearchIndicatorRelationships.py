import re

import demistomock as demisto
from CommonServerPython import *

from CommonServerUserPython import *

# --------------------------------------------------- Helper functions---------------------------------------------


def to_context(relationshipsData: dict, verbose: bool) -> dict:
    """
    Create context entries from the relationships returned from the searchRelationships command.

    :type relationships: ``list``
    :param relationships: list of dict of relationships from the searchRelationships command.

    :type verbose: ``bool``
    :param verbose: True if extended context should return, False for basic.

    :return: list of context for each relationship.
    :rtype: ``list``
    """
    demisto.debug(f"{relationshipsData=}")
    searchAfter = relationshipsData.get("SearchAfter", None)
    relationships = relationshipsData.get("data", []) or []
    context_dict: dict = {
        "Relationships": [],
        "RelationshipsPagination": [],
    }
    for relationship in relationships:
        relationships_context = {
            "EntityA": relationship["entityA"],
            "EntityAType": relationship["entityAType"],
            "EntityB": relationship["entityB"],
            "EntityBType": relationship["entityBType"],
            "Relationship": relationship["name"],
            "Reverse": relationship["reverseName"],
            "ID": relationship["id"],
        }
        if verbose:
            relationships_context["Type"] = relationship.get("type", "")

            sources = relationship.get("sources")
            if sources:
                relationships_context["Reliability"] = sources[0].get("reliability", "")
                relationships_context["Brand"] = sources[0].get("brand", "")

            custom_fields = relationship.get("CustomFields", {})
            if custom_fields:
                relationships_context["Revoked"] = custom_fields.get("revoked", "")
                relationships_context["FirstSeenBySource"] = custom_fields.get("firstseenbysource", "")
                relationships_context["LastSeenBySource"] = custom_fields.get("lastseenbysource", "")
                relationships_context["Description"] = custom_fields.get("description", "")

        context_dict["Relationships"].append(relationships_context)

    context_dict["RelationshipsPagination"].append(searchAfter) if searchAfter else []
    return context_dict


def handle_stix_types(entities_types: str) -> str:
    entities_types = argToList(entities_types)
    for e_type in entities_types:
        FeedIndicatorType.indicator_type_by_server_version(e_type)
    return ",".join(str(x) for x in entities_types).replace(", ", ",")


def search_relationships_fromversion_6_6_0(args: dict) -> dict:
    for list_arg in ["entities", "entityTypes", "relationshipNames"]:
        args[list_arg] = argToList(args[list_arg]) if args[list_arg] else None
    res = demisto.searchRelationships(args)
    return res


def search_relationships_toversion_6_5_0(args: dict) -> dict:
    res = demisto.executeCommand("searchRelationships", args)
    if is_error(res[0]):
        raise Exception("Error in searchRelationships command - {}".format(res[0]["Contents"]))
    return res[0].get("Contents", {})


def search_relationships(
    entities: Optional[str] = None,
    entities_types: Optional[str] = None,
    relationships: Optional[str] = None,
    limit: Optional[int] = None,
    query: Optional[str] = None,
    searchAfter: Optional[List[str]] = None,
) -> dict:
    args = {
        "entities": entities,
        "entityTypes": entities_types,
        "relationshipNames": relationships,
        "size": limit,
        "query": query,
        "searchAfter": searchAfter,
    }
    if is_demisto_version_ge("6.6.0"):
        return search_relationships_fromversion_6_6_0(args)
    return search_relationships_toversion_6_5_0(args)


""" MAIN FUNCTION """


def main():  # pragma: no cover
    try:
        args = demisto.args()
        entities = args.get("entities", "")
        entities_types = args.get("entities_types", "")
        relationships = args.get("relationships", "")
        limit = int(args.get("limit", "20"))
        verbose = argToBoolean(args.get("verbose", "false"))
        revoked = argToBoolean(args.get("revoked", "false"))
        query = "revoked:T" if revoked else "revoked:F"
        searchAfter = argToList(args.get("searchAfter", ""))
        handle_stix_types(entities_types)

        if relationship_search_results := search_relationships(
            entities, entities_types, relationships, limit, query, searchAfter
        ):
            context = to_context(relationship_search_results, verbose)
        else:
            context = {}
        hr = tableToMarkdown(
            "Relationships",
            context.get("Relationships", []),
            headers=["EntityA", "EntityAType", "EntityB", "EntityBType", "Relationship"],
            headerTransform=lambda header: re.sub(r"\B([A-Z])", r" \1", header),
        )
        return_results(
            CommandResults(
                readable_output=hr,
                outputs=context,
                outputs_key_field="ID",
            )
        )

    except Exception as e:
        return_error(f"Failed to execute SearchIndicatorRelationships automation. Error: {e!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
