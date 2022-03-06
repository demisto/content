import demistomock as demisto
import json


def test_main(mocker):
    from ParseHTMLTables import main

    test_data = [
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                      <tr>
                        <th>1.head1</th>
                        <th>1.head2</th>
                      </tr>
                      <tr>
                        <td>1.item-1-1</td>
                        <td>1.item-1-2</td>
                      </tr>
                      <tr>
                        <td>1.item-2-1</td>
                        <td>1.item-2-2</td>
                      </tr>
                    </table>

                    table2
                    <table>
                      <tr>
                        <th>2.head1</th>
                        <th>2.head2</th>
                      </tr>
                      <tr>
                        <td>2.item-1-1</td>
                        <td>2.item-1-2</td>
                      </tr>
                      <tr>
                        <td>2.item-2-1</td>
                        <td>2.item-2-2</td>
                      </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    "table1": [
                        {
                            "1.head1": "1.item-1-1",
                            "1.head2": "1.item-1-2"
                        },
                        {
                            "1.head1": "1.item-2-1",
                            "1.head2": "1.item-2-2"
                        }
                    ]
                },
                {
                    "table2": [
                        {
                            "2.head1": "2.item-1-1",
                            "2.head2": "2.item-1-2"
                        },
                        {
                            "2.head1": "2.item-2-1",
                            "2.head2": "2.item-2-2"
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                      <tr>
                        <th>1.head1</th>
                        <th>1.head2</th>
                      </tr>
                      <tr>
                        <td>1.item-1-1</td>
                        <td>1.item-1-2</td>
                      </tr>
                      <tr>
                        <td>1.item-2-1</td>
                        <td>1.item-2-2</td>
                      </tr>
                    </table>

                    <h1>table2</h1>
                    <table>
                      <tr>
                        <th>2.head1</th>
                        <th>2.head2</th>
                      </tr>
                      <tr>
                        <td>2.item-1-1</td>
                        <td>2.item-1-2</td>
                      </tr>
                      <tr>
                        <td>2.item-2-1</td>
                        <td>2.item-2-2</td>
                      </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    "table1": [
                        {
                            "1.head1": "1.item-1-1",
                            "1.head2": "1.item-1-2"
                        },
                        {
                            "1.head1": "1.item-2-1",
                            "1.head2": "1.item-2-2"
                        }
                    ]
                },
                {
                    "table2": [
                        {
                            "2.head1": "2.item-1-1",
                            "2.head2": "2.item-1-2"
                        },
                        {
                            "2.head1": "2.item-2-1",
                            "2.head2": "2.item-2-2"
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                      <tr>
                        <th>1.head1</th>
                        <th>1.head2</th>
                      </tr>
                      <tr>
                        <td>1.item-1-1</td>
                        <td>1.item-1-2</td>
                      </tr>
                      <tr>
                        <td>1.item-2-1</td>
                        <td>1.item-2-2</td>
                      </tr>
                    </table>

                    <h1>tab<strong>l</strong>e2</h1>
                    <table>
                      <tr>
                        <th>2.head1</th>
                        <th>2.head2</th>
                      </tr>
                      <tr>
                        <td>2.item-1-1</td>
                        <td>2.item-1-2</td>
                      </tr>
                      <tr>
                        <td>2.item-2-1</td>
                        <td>2.item-2-2</td>
                      </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    "table1": [
                        {
                            "1.head1": "1.item-1-1",
                            "1.head2": "1.item-1-2"
                        },
                        {
                            "1.head1": "1.item-2-1",
                            "1.head2": "1.item-2-2"
                        }
                    ]
                },
                {
                    "table2": [
                        {
                            "2.head1": "2.item-1-1",
                            "2.head2": "2.item-1-2"
                        },
                        {
                            "2.head1": "2.item-2-1",
                            "2.head2": "2.item-2-2"
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                      <tr>
                        <th>1.head1</th>
                        <th>1.head2</th>
                      </tr>
                      <tr>
                        <td>1.item-1-1</td>
                        <td>1.item-1-2</td>
                      </tr>
                      <tr>
                        <td>1.item-2-1</td>
                        <td>1.item-2-2</td>
                      </tr>
                    </table>

                    tab<strong>l</strong>e2
                    <table>
                      <tr>
                        <th>2.head1</th>
                        <th>2.head2</th>
                      </tr>
                      <tr>
                        <td>2.item-1-1</td>
                        <td>2.item-1-2</td>
                      </tr>
                      <tr>
                        <td>2.item-2-1</td>
                        <td>2.item-2-2</td>
                      </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    "table1": [
                        {
                            "1.head1": "1.item-1-1",
                            "1.head2": "1.item-1-2"
                        },
                        {
                            "1.head1": "1.item-2-1",
                            "1.head2": "1.item-2-2"
                        }
                    ]
                },
                {
                    "table2": [
                        {
                            "2.head1": "2.item-1-1",
                            "2.head2": "2.item-1-2"
                        },
                        {
                            "2.head1": "2.item-2-1",
                            "2.head2": "2.item-2-2"
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                      <tr>
                        <th>1.head1</th>
                        <th>1.head2</th>
                      </tr>
                      <tr>
                        <td>1.item-1-1</td>
                        <td>1.item-1-2</td>
                      </tr>
                      <tr>
                        <td>1.item-2-1</td>
                        <td>1.item-2-2</td>
                      </tr>
                    </table>

                    <table>
                      <tr>
                        <th>2.head1</th>
                        <th>2.head2</th>
                      </tr>
                      <tr>
                        <td>2.item-1-1</td>
                        <td>2.item-1-2</td>
                      </tr>
                      <tr>
                        <td>2.item-2-1</td>
                        <td>2.item-2-2</td>
                      </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    "table1": [
                        {
                            "1.head1": "1.item-1-1",
                            "1.head2": "1.item-1-2"
                        },
                        {
                            "1.head1": "1.item-2-1",
                            "1.head2": "1.item-2-2"
                        }
                    ]
                },
                {
                    "No Title": [
                        {
                            "2.head1": "2.item-1-1",
                            "2.head2": "2.item-1-2"
                        },
                        {
                            "2.head1": "2.item-2-1",
                            "2.head2": "2.item-2-2"
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table   1</h1>
                    <table>
                      <tr>
                        <th>1.head1</th>
                        <th>1.head2</th>
                      </tr>
                      <tr>
                        <td>1.item-1-1</td>
                        <td>1.item-1-2</td>
                      </tr>
                      <tr>
                        <td>1.item-2-1</td>
                        <td>1.item-2-2</td>
                      </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    "table 1": [
                        {
                            "1.head1": "1.item-1-1",
                            "1.head2": "1.item-1-2"
                        },
                        {
                            "1.head1": "1.item-2-1",
                            "1.head2": "1.item-2-2"
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                        <tr>
                            <td colspan="2" rowspan="3">item-x</td>
                            <td>item1-3</td>
                        </tr>
                        <tr>
                            <td>item2-3</td>
                        </tr>
                        <tr>
                            <td>item3-3</td>
                        </tr>
                        <tr>
                            <td>item4-1</td>
                            <td>item4-2</td>
                            <td>item4-3</td>
                        </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    'table1': [
                        {
                            'cell0': 'item-x',
                            'cell1': 'item-x',
                            'cell2': 'item1-3'
                        },
                        {
                            'cell0': 'item-x',
                            'cell1': 'item-x',
                            'cell2': 'item2-3'
                        },
                        {
                            'cell0': 'item-x',
                            'cell1': 'item-x',
                            'cell2': 'item3-3'
                        },
                        {
                            'cell0': 'item4-1',
                            'cell1': 'item4-2',
                            'cell2': 'item4-3'
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                        <tr>
                            <td rowspan="3">item-x</td>
                            <td>item1-1</td>
                            <td>item1-2</td>
                        </tr>
                        <tr>
                            <td>item2-1</td>
                            <td>item2-2</td>
                        </tr>
                        <tr>
                            <td>item3-1</td>
                            <td>item3-2</td>
                        </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    'table1': [
                        {
                            'cell0': 'item-x',
                            'cell1': 'item1-1',
                            'cell2': 'item1-2'
                        },
                        {
                            'cell0': 'item-x',
                            'cell1': 'item2-1',
                            'cell2': 'item2-2'
                        },
                        {
                            'cell0': 'item-x',
                            'cell1': 'item3-1',
                            'cell2': 'item3-2'
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                        <tr>
                            <td rowspan="3">item-x</td>
                            <td>item1-1</td>
                            <td>item1-2</td>
                        </tr>
                        <tr>
                            <td colspan="2">item2-1</td>
                        </tr>
                        <tr>
                            <td>item3-1</td>
                            <td>item3-2</td>
                        </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    'table1': [
                        {
                            'cell0': 'item-x',
                            'cell1': 'item1-1',
                            'cell2': 'item1-2'
                        },
                        {
                            'cell0': 'item-x',
                            'cell1': 'item2-1',
                            'cell2': 'item2-1'
                        },
                        {
                            'cell0': 'item-x',
                            'cell1': 'item3-1',
                            'cell2': 'item3-2'
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                        <tr>
                            <th rowspan="2">item-x</th>
                            <th>head1-1</th>
                            <th>head1-2</th>
                        </tr>
                        <tr>
                            <th>head2-1</th>
                            <th>head2-2</th>
                        </tr>
                        <tr>
                            <td>item1-1</td>
                            <td>item1-2</td>
                            <td>item1-3</td>
                        </tr>
                        <tr>
                            <td>item2-1</td>
                            <td>item2-2</td>
                            <td>item2-3</td>
                        </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    'table1': [
                        {
                            'item-x': 'item1-1',
                            'head1-1': 'item1-2',
                            'head1-2': 'item1-3'
                        },
                        {
                            'item-x': 'item2-1',
                            'head1-1': 'item2-2',
                            'head1-2': 'item2-3'
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                      <tr>
                        <th>head</th>
                      </tr>
                      <tr>
                        <td>item</td>
                      </tr>
                    </table>
                </html>
                    """,
            "results": [
                {
                    'table1': {
                        'head':
                        'item'
                    }
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                        <tr>
                            <td>head1</td>
                            <td>head2</td>
                            <td>head3</td>
                        </tr>
                        <tr>
                            <td>item1-1</td>
                            <td>item1-2</td>
                            <td>item1-3</td>
                        </tr>
                        <tr>
                            <td>item2-1</td>
                            <td>item2-2</td>
                            <td>item2-3</td>
                        </tr>
                    </table>
                </html>
                    """,
            "default_header_line": "first_row",
            "results": [
                {
                    'table1': [
                        {
                            'head1': 'item1-1',
                            'head2': 'item1-2',
                            'head3': 'item1-3'
                        },
                        {
                            'head1': 'item2-1',
                            'head2': 'item2-2',
                            'head3': 'item2-3'
                        }
                    ]
                }
            ]
        },
        {
            "value": """
                <html>
                    <h1>table1</h1>
                    <table>
                        <tr>
                            <td>head1</td>
                            <td>item1-1</td>
                            <td>item1-2</td>
                        </tr>
                        <tr>
                            <td>head2</td>
                            <td>item2-1</td>
                            <td>item2-2</td>
                        </tr>
                        <tr>
                            <td>head3</td>
                            <td>item3-1</td>
                            <td>item3-2</td>
                        </tr>
                    </table>
                </html>
                    """,
            "default_header_line": "first_column",
            "results": [
                {
                    'table1': [
                        {
                            'head1': 'item1-1',
                            'head2': 'item2-1',
                            'head3': 'item3-1'
                        },
                        {
                            'head1': 'item1-2',
                            'head2': 'item2-2',
                            'head3': 'item3-2'
                        }
                    ]
                }
            ]
        }
    ]

    for t in test_data:
        mocker.patch.object(demisto, 'args', return_value={
            'value': t['value'],
            'default_header_line': t.get('default_header_line')
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert json.dumps(results) == json.dumps(t['results'])
