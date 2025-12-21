import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import re
                                                                
def filter_relationships_by_entity_types(entities, entities_types, relationships, limit):
    """
    Filters indicator relationships by entity types using pagination.

    Args:
        entities: List of entities to search for relationships
        entities_types: List of entity types to filter by (EntityA or EntityB must match)
        relationships: List of relationship types to search for
        limit: Maximum number of filtered relationships to return

    Returns:
        list: Filtered relationships where EntityA or EntityB type matches entities_types
    """
    filtered_relationships: list = []
    searchAfter = None
    iteration = 0
    while len(filtered_relationships) < limit:
        search_params = {
            "entities": entities,
            "relationships": relationships,
        }

        if searchAfter:
            search_params["searchAfter"] = searchAfter

        res = demisto.executeCommand("SearchIndicatorRelationships", search_params)

        if not res or len(res) == 0:
            demisto.debug("No response received from SearchIndicatorRelationships")
            break

        data = demisto.get(res[0], "Contents") or {}
        demisto.debug(f"{iteration=}, Received data: {data}")
        iteration += 1
        if not data or data.get("Relationships") is None:
            demisto.debug(f"Invalid or empty data received: {data}")
            break

        for relationship in data.get("Relationships", []):
            if relationship["EntityAType"] in entities_types or relationship["EntityBType"] in entities_types:
                filtered_relationships.append(relationship)

                if len(filtered_relationships) >= limit:
                    break

        searchAfter_list = data.get("RelationshipsPagination", [])
        searchAfter = searchAfter_list[0] if searchAfter_list else None
        demisto.debug(f"SearchAfter updated: {searchAfter}")

        if not searchAfter or len(filtered_relationships) >= limit:
            break

    demisto.debug(f"{filtered_relationships=}")
    return filtered_relationships


def get_relationships(
    entities: Optional[list[str]] = None,
    entities_types: Optional[list[str]] = None,
    relationships: Optional[list[str]] = None,
    limit: int = 20,
) -> list:
    """
    Retrieves indicator relationships based on specified entities, entity types, and relationships.

    Args:
        entities (Optional[list[str]]): List of entity values to search for relationships
        entities_types (Optional[list[str]]): List of entity types to filter relationships by
        relationships (Optional[list[str]]): List of relationship types to search for
        limit (int): Maximum number of relationships to return (default: 20)

    Returns:
        list: List of relationships matching the search criteria. If entities_types is provided,
                returns filtered relationships where EntityA or EntityB type matches entities_types.
                Returns empty list if no parameters are provided or no relationships found.
    """
    if not entities and not entities_types and not relationships:
        return []

    search_params = {
        "entities": entities,
        "entities_types": entities_types,
        "relationships": relationships,
        "limit": limit,
    }
    remove_nulls_from_dictionary(search_params)
    if entities_types:
        filtered_relationships = filter_relationships_by_entity_types(entities, entities_types, relationships, limit)
        return filtered_relationships

    res = demisto.executeCommand("SearchIndicatorRelationships", search_params)
    if not res or len(res) == 0:
        return []

    data = demisto.get(res[0], "Contents") or {}
    return data.get("Relationships", []) or []


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
            headers=[
                "EntityA",
                "EntityAType",
                "EntityB",
                "EntityBType",
                "Relationship",
            ],
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
    except Exception as ex:
        return_error(f"Failed to execute SearchIndicatorRelationshipsAgentix. Error: {str(ex)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
