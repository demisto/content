import feedparser

TEXT_EXCEEDED_MAX_SIZE = "<p> 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203 204 205 206 207 208 209 210 211 212 213 214 215 216 217 218 219 220 221 222 223 224 225 226 227 228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 250 251 252 253 254 255 256 257 258 259 260 261 262 263 264 265 266 267 268 269 270 271 272 273 274 275 276 277 278 279 280 281 282 283 284 285 286 287 288 289 290 291 292 293 294 295 296 297 298 299</p"
EXPECTED_OUTPUT_EXCEEDED_MAX_SIZE = "This is a dumped content of the article. Use the link under Publications field to read the full article. \n\n 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 73 74 75 76 77 78 79 80 81 82 83 84 85 86 87 88 89 90 91 92 93 94 95 96 97 98 99 100 101 102 103 104 105 106 107 108 109 110 111 112 113 114 115 116 117 118 119 120 121 122 123 124 125 126 127 128 129 130 131 132 133 134 135 136 137 138 139 140 141 142 143 144 145 146 147 148 149 150 151 152 153 154 155 156 157 158 159 160 161 162 163 164 165 166 167 168 169 170 171 172 173 174 175 176 177 178 179 180 181 182 183 184 185 186 187 188 189 190 191 192 193 194 195 196 197 198 199 200 201 202 203 204 205 206 207 208 209 210 211 212 213 214 215 216 217 218 219 220 221 222 223 224 225 226 227 228 229 230 231 232 233 234 235 236 237 238 239 240 241 242 243 244 245 246 247 248 249 25 This is truncated text, report content was too big."

TEXT_MAX_SIZE = "<p>This is short text</p>"
EXPECTED_OUTPUT_MAX_SIZE = "This is a dumped content of the article. Use the link under Publications field to read the full article. \n\n This is short text"

TEST_DATA_MAX_SIZE = [(TEXT_EXCEEDED_MAX_SIZE, EXPECTED_OUTPUT_EXCEEDED_MAX_SIZE), (TEXT_MAX_SIZE, EXPECTED_OUTPUT_MAX_SIZE)]
HTML_CONTENT = """<div>
<p>p in div</p>
<div>
<span>div</span>
</div>
<p>p</p>
</div>
<ul>
    <li>
        <div >
            <p>li inside ul</p>
        </div>
    </li>
</ul>
<ol>
  <li>Coffee</li>
  <li>Tea</li>
  <li>Milk</li>
</ol>
<table>
  <tr>
    <th>Month</th>
    <th>Savings</th>
  </tr>
  <tr>
    <td>January</td>
    <td>$100</td>
  </tr>
</table>
<script type="text/javascript">
    var appInsights=10;
</script>
<link rel="canonical" href="https://test.com/"/>
<h1> This is h1 </h1>
<h7> This is h7 </h7>
"""
FEED_DATA = [({'bozo': False,
             'entries': [feedparser.util.FeedParserDict({'title': 'Test Article, with comma',
                                                         'link': 'https://test-article.com/',
                                                         'authors': [{'name': 'Example'}],
                                                         'published': 'Fri, 18 Jun 2021 15:35:41 +0000',
                                                         'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                                         'id': 'xxxx',
                                                         'guidislink': False,
                                                         'summary': "this is summary"})]
               }, [{
                   "type": 'Report',
                   "value": "Test Article with comma",
                   "rawJSON": {'value': {'authors': [{'name': 'Example'}],
                                         'guidislink': False,
                                         'id': 'xxxx',
                                         'link': 'https://test-article.com/',
                                         'published': 'Fri, 18 Jun 2021 15:35:41 +0000',
                                         'summary': 'this is summary',
                                         'tags': [{'label': None,
                                                   'scheme': None,
                                                   'term': 'Malware'}],
                                         'title': 'Test Article, with comma'},
                               'type': 'Report', "firstseenbysource": '2021-06-18T15:35:41'},
                   "reliability": "F - Reliability cannot be judged",
                   "fields": {
                       'publications': [{
                           'timestamp': '2021-06-18T15:35:41',
                           'link': 'https://test-article.com/',
                           'source': 'test.com',
                           'title': 'Test Article, with comma'
                       }],
                       'rssfeedrawcontent': 'test description',
                       'tags': [],
                       'description': 'this is summary'
                   }}])]


FEED_DATA_NO_PUBLISH_FIELD = [({'bozo': False,
                                'entries': [feedparser.util.FeedParserDict({'title': 'Test Article, with comma',
                                                                            'link': 'https://test-article.com/',
                                                                            'authors': [{'name': 'Example'}],
                                                                            'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                                                            'id': 'xxxx',
                                                                            'guidislink': False,
                                                                            'summary': "this is summary"})]
                                }, [{
                                    "type": 'Report',
                                    "value": "Test Article with comma",
                                    "rawJSON": {'value': {'authors': [{'name': 'Example'}],
                                                          'guidislink': False,
                                                          'id': 'xxxx',
                                                          'link': 'https://test-article.com/',
                                                          'summary': 'this is summary',
                                                          'tags': [{'label': None,
                                                                    'scheme': None,
                                                                    'term': 'Malware'}],
                                                          'title': 'Test Article, with comma'},
                                                'type': 'Report', "firstseenbysource": ''},
                                    "reliability": "F - Reliability cannot be judged",
                                    "fields": {
                                        'publications': [{
                                            'timestamp': '',
                                            'link': 'https://test-article.com/',
                                            'source': 'test.com',
                                            'title': 'Test Article, with comma'
                                        }],
                                        'rssfeedrawcontent': 'test description',
                                        'tags': [],
                                        'description': 'this is summary'
                                    }}])]
