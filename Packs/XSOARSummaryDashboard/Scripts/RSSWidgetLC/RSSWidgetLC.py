import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import email.utils
from time import mktime

import feedparser
from feedparser.util import FeedParserDict
from markdownify import markdownify


def parse_feed_data(url):
    """Parses the data from the RSS feed.

    Args:
        feed_response (str): The raw data from the RSS feed.

    Returns:
        FeedParserDict: Parsed RSS feed data.
    """
    try:
        return feedparser.parse(url)
    except Exception as err:
        raise DemistoException(f"Failed to parse feed.\nError:\n{str(err)}", exception=err)


def collect_entries_data_from_response(parsed_feed_data: FeedParserDict, limit: Union[int, None]) -> List[Dict[str, Any]]:
    """Collects relevant data from the parsed RSS feed entries.

    Args:
        parsed_feed_data (FeedParserDict): Parsed RSS feed data.
        limit (Union[int, None]): Maximum number of results to return.

    Returns:
        List[Dict[str, Any]]: The data from the RSS feed relevant for the widget.
    """
    entries_data: List[Dict[str, Any]] = []
    if not parsed_feed_data:
        raise DemistoException("Could not parse feed data.")

    if not limit:
        return entries_data

    for entry in parsed_feed_data.entries:
        if entry:
            published = email.utils.parsedate(entry.published)
            if not published:
                continue

            published_dt = datetime.fromtimestamp(mktime(published))
            published_formatted = published_dt.strftime('%B %-d, %Y %-I:%M %p')

            entries_data.append(
                {
                    'timestamp': published_formatted,
                    'link': entry.get('link'),
                    'title': entry.get('title'),
                    'summary': markdownify(entry.get('summary')),
                    'author': entry.get('author'),
                }
            )

            if limit != 'all':
                limit -= 1

                if limit == 0:
                    break

    return entries_data


def create_widget_content(entries_data: List[Dict[str, Any]]) -> str:
    """Creates the human readable text for the widget.

    Args:
        entries_data (List[Dict[str, Any]]): The data from the  RSS feed relevant for the widget.

    Returns:
        str: The widget's content.
    """
    content: str = ''

    for entry_data in entries_data:
        content += f'**[{entry_data["title"]}]({entry_data["link"]})**\n'

        # Markdown formatting is supported from 6.5
        if is_demisto_version_ge('6.5'):
            content += '{{color:#89A5C1}}' + f'(*Posted {entry_data["timestamp"]} by {entry_data["author"]}*)\n'
        else:
            content += f'*Posted {entry_data["timestamp"]} by {entry_data["author"]}*\n'

        content += f'{entry_data["summary"]}\n'
        content += '\n\n'

    if not content:
        content = '## No entries were found.'

    return content


def main():
    args = demisto.args()

    limit = sys.maxsize if not args.get('limit') else arg_to_number(args.get('limit'))
    url = "https://live.paloaltonetworks.com/twzvq79624/rss/search?filter=includeBlogs%2Clabels&" \
          "collapse_discussion=true&search_type=thread&include_blogs=true&labels=cortex+xsoar"

    try:
        parsed_feed_data = parse_feed_data(url)
        entries_data = collect_entries_data_from_response(parsed_feed_data, limit)
        content = create_widget_content(entries_data)
    except Exception as e:
        return_error(str(e))

    return_results({
        'Type': EntryType.NOTE,
        'ContentsFormat': EntryFormat.MARKDOWN,
        'Contents': content,
    })


if __name__ in ('__builtin__', 'builtins', '__main__'):  # pragma: no cover
    main()
