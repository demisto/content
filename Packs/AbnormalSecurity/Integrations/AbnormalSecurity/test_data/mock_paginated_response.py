#!/usr/bin/env python
# -*- coding: utf-8 -*- # noqa: UP009

"""
Utility module for generating paginated mock responses for testing.
This module provides functions to create realistic paginated responses
with configurable properties for testing API pagination.

Templates for items (threats, cases, campaigns) are loaded from template_items.json.
"""

import copy
import uuid
import json
import os


def util_load_json(path):
    """Load a JSON file from the given path."""
    with open(path, encoding="utf-8") as f:
        return json.loads(f.read())


def create_paginated_response(template_item, item_key, count=10, items_per_page=None, max_pages=None):
    """
    Create a paginated mock response with multiple pages based on a template item.

    Args:
        template_item (dict): Template for a single item (e.g., a single threat, case, or campaign)
        item_key (str): The key under which items are stored (e.g., 'threats', 'cases', 'campaigns')
        count (int): Total number of items to generate
        items_per_page (int, optional): Number of items per page. If None, all items in a single page.
        max_pages (int, optional): Maximum number of pages to generate. If None, generate enough pages for all items.

    Returns:
        dict: A dictionary with all generated items and pagination information
    """
    # Generate the items
    items = []
    for i in range(count):
        item = copy.deepcopy(template_item)

        # Add unique ID if it exists in template
        for id_field in ["threatId", "caseId", "campaignId"]:
            if id_field in item:
                item[id_field] = f"{id_field.replace('Id', '')}-{i+1}"

        # Add any other unique identifiers if needed
        if "abxMessageId" in item:
            item["abxMessageId"] = str(uuid.uuid4())

        items.append(item)

    # Create the paginated structure
    if items_per_page is None:
        # Return all items in a single page
        return {item_key: items, "pageNumber": 1, "nextPageNumber": None}

    # Calculate how many pages we need
    total_pages = (count + items_per_page - 1) // items_per_page
    if max_pages is not None:
        total_pages = min(total_pages, max_pages)

    # Create the pages
    pages = {}
    for page_num in range(1, total_pages + 1):
        start_idx = (page_num - 1) * items_per_page
        end_idx = min(start_idx + items_per_page, count)

        next_page = page_num + 1 if page_num < total_pages else None

        pages[f"page{page_num}"] = {item_key: items[start_idx:end_idx], "pageNumber": page_num, "nextPageNumber": next_page}

    return pages


def create_mock_paginator_side_effect(item_type):
    """
    Create a function that can be used as a side effect for mock API calls with pagination.

    Args:
        item_type (str): The type of item to use as a template ('threat', 'case', or 'campaign')
                         This is used to load the appropriate template and derive the item_key.

    Returns:
        function: A function to use as a side effect for mocked API calls
    """
    # Map item types to their plural forms for API responses
    item_key_map = {"threat": "threats", "case": "cases", "campaign": "campaigns"}

    # Derive the item_key from the item_type
    item_key = item_key_map.get(item_type)
    if not item_key:
        raise ValueError(f"Unknown item type: {item_type}. Must be one of: {', '.join(item_key_map.keys())}")

    # Load template items from JSON
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, "template_items.json")
    template_items = util_load_json(template_path)

    # Get the list template for the current item type
    template_item = template_items.get(item_type)
    if not template_item:
        raise ValueError(f"Template for {item_type} not found in template_items.json")

    # Create a large pool of items to draw from
    all_items = []
    for _i in range(100):  # Create 100 items as a pool
        item = copy.deepcopy(template_item)

        all_items.append(item)

    def side_effect(**kwargs):
        """Side effect function for mocking paginated API responses"""
        page_number = kwargs.get("page_number", 1)
        page_size = kwargs.get("page_size", 10)

        # Calculate start and end indices
        start_idx = (page_number - 1) * page_size
        end_idx = min(start_idx + page_size, len(all_items))

        # If start_idx is beyond our data, return empty page
        if start_idx >= len(all_items):
            return {item_key: [], "pageNumber": page_number, "nextPageNumber": None}

        # Get the requested slice of items
        page_items = all_items[start_idx:end_idx]

        # Determine if there's a next page
        next_page = page_number + 1 if end_idx < len(all_items) else None

        # Build the response
        response = {item_key: page_items, "pageNumber": page_number, "nextPageNumber": next_page}

        return response

    return side_effect


def create_mock_detail_side_effect(item_type):
    """
    Create a function that can be used as a side effect for mock API detail calls.

    Args:
        item_type (str): The type of item to use as a template ('threat', 'case', or 'campaign')
                         This is used to load the appropriate detail template.

    Returns:
        function: A function to use as a side effect for mocked API detail calls
    """
    # Load template items from JSON
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(current_dir, "template_items.json")
    template_items = util_load_json(template_path)

    # Load the detail template
    detail_template_key = f"{item_type}_detail"
    detail_template = template_items.get(detail_template_key)
    if not detail_template:
        raise ValueError(f"Detail template for {detail_template_key} not found in template_items.json")

    # Create a pool of detail items
    detail_items = {}
    for i in range(100):
        item_id = f"{item_type}-{i+1}"
        detail_item = copy.deepcopy(detail_template)

        # Set the correct ID
        for id_field in ["threatId", "caseId", "campaignId"]:
            if id_field in detail_item:
                detail_item[id_field] = item_id

        detail_items[item_id] = detail_item

    def side_effect(item_id, **kwargs):
        """Side effect function for mocking detail API responses"""
        # If we have a detail for this ID, return it
        if item_id in detail_items:
            return detail_items[item_id]

        # If not, create a new one based on the template
        detail_item = copy.deepcopy(detail_template)
        for id_field in ["threatId", "caseId", "campaignId"]:
            if id_field in detail_item:
                detail_item[id_field] = item_id

        # Add the item to our cache
        detail_items[item_id] = detail_item

        return detail_item

    return side_effect
