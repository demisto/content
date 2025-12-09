import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def filter_relationships_by_entity_types(entities, entities_types, relationships, limit):
    filtered_relationships: list = []
    searchAfter = None

    while len(filtered_relationships) < limit:
        # Prepare search parameters
        search_params = {
            "entities": entities,
            "relationships": relationships,
        }

        # Add searchAfter if it exists
        if searchAfter:
            search_params["searchAfter"] = searchAfter

        # Execute search command
        res = demisto.executeCommand("SearchIndicatorRelationships", search_params)

        # Validate response
        if not res or len(res) == 0:
            demisto.debug("No response received from SearchIndicatorRelationships")
            break

        # Extract contents safely
        data = demisto.get(res[0], "Contents") or {}
        demisto.debug(f"Received data: {data}")
        # Check if data is valid
        if not data or data.get("Relationships") is None:
            demisto.debug(f"Invalid or empty data received: {data}")
            break

        for relationship in data.get("Relationships", []):
            if (
                not entities_types
                or relationship["EntityAType"] in entities_types
                or relationship["EntityBType"] in entities_types
            ):
                filtered_relationships.append(relationship)

                if len(filtered_relationships) >= limit:
                    break

        searchAfter_list = data.get("RelationshipsPagination", [])
        searchAfter = searchAfter_list[0] if searchAfter_list else None
        demisto.debug(f"SearchAfter updated: {searchAfter}")

        if not searchAfter or len(filtered_relationships) >= limit:
            break

    demisto.debug(f"Finished searching relationships with given criteria: {filtered_relationships}")
    return filtered_relationships


def get_relationships(
    entities: Optional[list[str]] = None,
    entities_types: Optional[list[str]] = None,
    relationships: Optional[list[str]] = None,
    limit: int = 20,
) -> list:
    if not entities and not entities_types and not relationships:
        return []

    search_params = {"entities": entities, "entities_types": entities_types, "relationships": relationships, "limit": limit}
    remove_nulls_from_dictionary(search_params)
    if entities_types:
        filtered_relationships = filter_relationships_by_entity_types(entities, entities_types, relationships, limit)
        return filtered_relationships

    res = demisto.executeCommand("SearchIndicatorRelationships", search_params)
    if not res or len(res) == 0:
        return []

    data = demisto.get(res[0], "Contents") or {}
    return data.get("Relationships") or []


def main():
    try:
        args = demisto.args()
        entities_types = args.pop("entities_types", "")
        entities = args.get("entities", "")
        relationships = args.get("relationships", "")
        limit = int(args.get("limit", "20"))

        relationships = get_relationships(entities, entities_types, relationships, limit)
        hr = tableToMarkdown(
            "Relationships",
            relationships,
            headers=["EntityA", "EntityAType", "EntityB", "EntityBType", "Relationship"],
            headerTransform=lambda header: re.sub(r"\B([A-Z])", r" \1", header),
        )
        return_results(
            CommandResults(
                readable_output=hr,
                outputs_prefix="Relationships",
                outputs=relationships,
                outputs_key_field="ID",
            )
        )
        # return_results(data)
    except Exception as ex:
        return_error(f"Failed to execute SearchIndicatorRelationshipsAgentix. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
