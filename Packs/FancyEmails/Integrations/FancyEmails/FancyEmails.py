from datetime import datetime

import demistomock as demisto  # noqa: F401
import pytz
from CommonServerPython import *  # noqa: F401


def main():
    params = demisto.params()
    background_color = params.get('BackgroundColor', '#272727')
    foreground_color = params.get('ForegroundColor', '#FFFFFF')
    banner_text_color = params.get('BannerTextColor', '#FFFFFF')
    banner_color = params.get('BannerColor', '#F51212')
    custom_css = params.get('CustomCss', '')
    local_timezone = params.get('TimeZone')
    alignlogo = params.get('AlignLogo')
    baselogo = params.get('Base64Logo')
    logoheight = params.get('LogoHeight')
    logowidth = params.get('LogoWidth')

    DEFAULT_CSS = f"""
    body{{
        font-family: arial;
    }}
    
    table {{
          border: 1px solid {background_color};
          border-collapse: collapse;
          width: 100%;
    }}
    
    th {{
        background-color:  {background_color};
        border: none;
        color: {foreground_color};
        text-align: left;
        padding: 0.5em;
    }}
    
    tr{{
        text-align: left;
    }}
    
    td{{
        padding: 0.5em;
    }}
    
    .banner{{
        text-align:center;
        color: {banner_text_color};
        background-color: {banner_color};
        width: 100%;
        display: block;
        font-size:1.2em
    }}
    
    .data-header {{
        padding: 0.5em;
    
    }}
    
    .data-cell {{
        padding:0.5em;
    }}
    
    .footer {{
        background-color:   {background_color};
        width: 100%;
        color:  {foreground_color};
        border-collapse: collapsed;
        border: none;
        padding: 0.5em;
    }}
    
    .footer-cell {{
    
    }}
    
    .footer-row {{
        background-color:   {background_color};
        width: 100%;
        text-align: center;
        font-size: 0.75em;
    }}
    
    .header {{
        background-color:  {background_color};
        width: 100%;
        text-align: center;
        color:  {foreground_color};
        padding: 0.5em;
    
    }}
    
    .header-text {{
        background-color:  {background_color};
        width: 100%;
        text-align: center;
    
        margin: auto;
    }}
    
    .logo{{
        margin: 1em;
    
    }}
    
    .logo-container{{
        width: 100%;
        margin-top: 1em;
        text-align: {alignlogo};
    }}
    
    {custom_css}
    """

    '''
        +++++ HTML MAKERS +++++
    '''

    def check_for_datetime(value, include_raw: bool = True):
        try:
            fancy_value = convert_timestamp_to_fancy_time(value)
            if include_raw:
                return f'{fancy_value}<br/><small>(raw: {value})</small>'
            else:
                return fancy_value
        except ValueError:
            return value

    def convert_timestamp_to_fancy_time(value):
        if value == "0001-01-01T00:00:00Z":
            return '-'
        value = value.split('.')[0]
        value = datetime.fromisoformat(value)
        pytz.timezone('UTC').localize(value)
        return value.astimezone(pytz.timezone(local_timezone)).strftime(f'%A %b-%d-%Y %-I:%M:%S%p {local_timezone}')

    def make_cell(value, include_raw: bool = True):
        value = check_for_datetime(value, include_raw)
        return f'<td class="data-cell">{value}</td>\n'

    def make_header(value):
        return f'<th class="data-header">{value}</th>\n'

    def make_row(value):
        return f'<tr>{value}</tr>\n'

    def make_rows(items, table_headers):
        data_rows = ''
        for item in items:
            row_data = ''
            for header in table_headers:
                row_data += make_cell(item.get(header, ''))
            data_rows += make_row(row_data)
        return data_rows

    def make_header_row(table_headers):
        '''
            ['header1', 'header2'] -> <tr><th>header1</th><th>header2</th></th>
        '''
        header_tags = map(make_header, table_headers)
        header_tags = ''.join(header_tags)
        return make_row(header_tags)

    def make_vertical_table_row(items, header):
        '''
            [{Object1}, {Object2}] -> <tr><th>Objec1t.header</th><td>Object1.value</td><td>Object2.value</td></tr>
        '''

        def extract_value(x):
            return x.get(header, '')

        values = list(map(extract_value, items))
        values = list(map(make_cell, values))
        values = ''.join(values)
        header = make_header(header)
        return make_row(header + values)

    def make_vertical_table(items, name='', table_headers=None):
        if not table_headers:
            table_headers = items[0].keys()

        data_rows = ''
        for header in table_headers:
            data_rows += make_vertical_table_row(items, header)

        return f'''
                <h3>
                    {name}
                </h3>
                <table>
                <tbody>
                    {data_rows}
                    </tbody>
                </table>
                '''

    def make_table(items, name='', table_headers=None):
        if not table_headers:
            table_headers = items[0].keys()

        header_row = make_header_row(table_headers)
        data_rows = make_rows(items, table_headers)
        return f'''
                <h3>
                    {name}
                </h3>
                <table>
                <thead>
                    {header_row}
                    </thead>
                    <tbody>
                    {data_rows}
                    </tbody>
                </table>
                '''

    def make_banner(text):
        return f'<div class="banner">{text}</div>'''

    def make_css(custom_css=''):
        css = DEFAULT_CSS + custom_css
        return f"<style>{css}</style>"

    def make_email_header(value):
        return f'''
            <table class="header">
                <tr>
                    <td>
                        <h2 class="header-text">
                            {value}
                        </h2>
                        </td>
                </tr>
            </table>
        '''

    def make_email_footer(line1, line2):
        return f'''
        <br/>
            <table class="footer">
                <tr class="footer-row">
                    <td class="footer-cell" style="font-size: 0.9em;">
                        {line1}
                    </td>
                </tr>
                <tr class="footer-row">
                    <td class="footer-cell">
                        {line2}
                    </td>
                </tr>
            </table>
        '''

    def make_logo():
        return f'''
            <div class='logo-container'>
                <img class='logo' height='{logoheight}' width='{logowidth}' src='{baselogo}' alt="Cortex Logo" />
            </div>
        '''

    '''
        +++++ DEMISTO HANDLERS +++++
    '''

    args = demisto.args()

    def make_table_command():
        headers = args.get('headers')
        items = args.get('items')
        name = args.get('name', '')
        vertical_table = bool(args.get('vertical_table', False))
        print_to_warroom = bool(args.get('print_to_warroom', False))
        include_css = args.get('include_css', False)

        headers = argToList(headers)

        if vertical_table:
            html_table = make_vertical_table(items, name, headers)
        else:
            html_table = make_table(items, name, headers)

        if include_css:
            html_table = make_css() + html_table

        results = CommandResults(
            outputs_prefix="FancyEmails.Table",
            outputs={'name': name,
                     'html': html_table},
            readable_output=html_table if print_to_warroom else "Table Created in the FancyEmails.Table Context",
        )
        return_results(results)

    def make_logo_command():
        return_results(make_logo())

    def make_email_command():
        body = args.get('body')
        banner = args.get('banner')
        header = args.get('header')
        custom_css = args.get('custom_css', '')

        print_to_warroom = bool(args.get('print_to_warroom', False))
        line1 = demisto.params().get('FooterLine1', '')
        line2 = demisto.params().get('FooterLine2', '')

        css = make_css(custom_css)
        banner = make_banner(banner) if banner else ''
        header = make_email_header(header)
        logo = make_logo()
        footer = make_email_footer(line1, line2)
        email_html = ''.join([css, banner, header, logo, body, footer, banner])

        results = CommandResults(
            outputs_prefix="FancyEmails.Email",
            outputs={'name': header,
                     'html': email_html},
            readable_output=email_html if print_to_warroom else "Email Created in the FancyEmails.Email Context",
        )

        return_results(results)

    def make_date_time_string():
        value = args.get('value')
        name = args.get('name')
        include_raw = args.get('include_raw', 'true').lower() == 'true'
        fancy_time = check_for_datetime(value, include_raw)

        results = CommandResults(
            outputs_prefix="FancyEmails.TimeString",
            outputs={
                'name': name,
                'html': fancy_time
            },
            readable_output=fancy_time
        )

        return_results(results)

    def test_module():
        return_results(True)

    command_map = {
        'fancy-email-make-table': make_table_command,
        'fancy-email-make-email': make_email_command,
        'fancy-email-make-timestring': make_date_time_string,
        'fancy-email-make-logo': make_logo_command,
        'test-module': test_module
    }

    command_map.get(demisto.command(), test_module)()


if __name__ == '__main__':
    main()
