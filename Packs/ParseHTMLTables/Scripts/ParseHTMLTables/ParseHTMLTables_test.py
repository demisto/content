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
        }
    ]
    for t in test_data:
        mocker.patch.object(demisto, 'args', return_value={
            'value': t['value']
        })
        mocker.patch.object(demisto, 'results')
        main()
        assert demisto.results.call_count == 1
        results = demisto.results.call_args[0][0]
        assert json.dumps(results) == json.dumps(t['results'])
