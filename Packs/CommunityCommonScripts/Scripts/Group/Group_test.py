from CommonServerPython import argToList  # noqa: F401
from group import group


def test_group_list():
    input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    data = argToList(input)
    chunk = 5
    structure = "List"
    delimiter = None
    outputs = group(data, chunk, structure, delimiter)
    assert outputs == [[1, 2, 3, 4, 5], [6, 7, 8, 9, 10]]


def test_group_string():
    input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    data = argToList(input)
    chunk = 5
    structure = "String"
    delimiter = None
    outputs = group(data, chunk, structure, delimiter)
    assert outputs == ["1,2,3,4,5", "6,7,8,9,10"]


def test_group_list_unequal():
    input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    data = argToList(input)
    chunk = 7
    structure = "List"
    delimiter = None
    outputs = group(data, chunk, structure, delimiter)
    assert outputs == [[1, 2, 3, 4, 5, 6, 7], [8, 9, 10]]


def test_group_string_unequal():
    input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    data = argToList(input)
    chunk = 7
    structure = "String"
    delimiter = None
    outputs = group(data, chunk, structure, delimiter)
    assert outputs == ["1,2,3,4,5,6,7", "8,9,10"]


def test_group_string_unequal_delimiter():
    input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    data = argToList(input)
    chunk = 3
    structure = "String"
    delimiter = "-"
    outputs = group(data, chunk, structure, delimiter)
    assert outputs == ["1-2-3", "4-5-6", "7-8-9", "10"]


def test_group_list_additional():
    input = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]
    data = argToList(input)
    chunk = 3
    structure = "List"
    delimiter = ","
    outputs = group(data, chunk, structure, delimiter)
    assert outputs == [["1", "2", "3"], ["4", "5", "6"], ["7", "8", "9"], ["10"]]


def test_group_string_additional():
    input = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]
    data = argToList(input)
    chunk = 3
    structure = "String"
    delimiter = ","
    outputs = group(data, chunk, structure, delimiter)
    assert outputs == ["1,2,3", "4,5,6", "7,8,9", "10"]
