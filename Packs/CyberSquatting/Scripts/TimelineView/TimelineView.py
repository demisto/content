import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# This script creates a timeline image of events and prints on the warroom
# sample imput
# !a_timeline_with_args header="[2010, 2011, 2012]" content="['content1 ', 'c2', 'c3']"


def timeline(header, content):
    header = eval(header)
    content = eval(content)
    css = '''<style>
    * {
      box-sizing: border-box;
    }

    body {
      background-color: #474e5d;
      font-family: Helvetica, sans-serif;
    }

    /* The actual timeline (the vertical ruler) */
    .timeline {
      position: relative;
      max-width: 1200px;
      margin: 0 auto;
    }

    /* The actual timeline (the vertical ruler) */
    .timeline::after {
      content: '';
      position: absolute;
      width: 6px;
      background-color: white;
      top: 0;
      bottom: 0;
      left: 50%;
      margin-left: -3px;
    }

    /* Container around content */
    .container {
      padding: 10px 40px;
      position: relative;
      background-color: inherit;
      width: 50%;
    }

    /* The circles on the timeline */
    .container::after {
      content: '';
      position: absolute;
      width: 25px;
      height: 25px;
      right: -17px;
      background-color: white;
      border: 4px solid #FF9F55;
      top: 15px;
      border-radius: 50%;
      z-index: 1;
    }

    /* Place the container to the left */
    .left {
      left: 0;
    }

    /* Place the container to the right */
    .right {
      left: 50%;
    }

    /* Add arrows to the left container (pointing right) */
    .left::before {
      content: \" \";
      height: 0;
      position: absolute;
      top: 22px;
      width: 0;
      z-index: 1;
      right: 30px;
      border: medium solid white;
      border-width: 10px 0 10px 10px;
      border-color: transparent transparent transparent white;
    }

    /* Add arrows to the right container (pointing left) */
    .right::before {
      content: \" \";
      height: 0;
      position: absolute;
      top: 22px;
      width: 0;
      z-index: 1;
      left: 30px;
      border: medium solid white;
      border-width: 10px 10px 10px 0;
      border-color: transparent white transparent transparent;
    }

    /* Fix the circle for containers on the right side */
    .right::after {
      left: -16px;
    }

    /* The actual content */
    .content {
      padding: 20px 30px;
      background-color: white;
      position: relative;
      border-radius: 6px;
    }

    /* Media queries - Responsive timeline on screens less than 600px wide */
    @media screen and (max-width: 600px) {
      /* Place the timelime to the left */
      .timeline::after {
      left: 31px;
      }

      /* Full-width containers */
      .container {
      width: 100%;
      padding-left: 70px;
      padding-right: 25px;
      }

      /* Make sure that all arrows are pointing leftwards */
      .container::before {
      left: 60px;
      border: medium solid white;
      border-width: 10px 10px 10px 0;
      border-color: transparent white transparent transparent;
      }

      /* Make sure all circles are at the same spot */
      .left::after, .right::after {
      left: 15px;
      }

      /* Make all right containers behave like the left ones */
      .right {
      left: 0%;
      }
    }
    </style>'''

    html = '''<div class=\"timeline\">
      <div class=\"container left\">
        <div class=\"content\">
          <h2>2017</h2>
          <p>Lorem ipsum dolor sit amet, .</p>
        </div>
      </div>
      <div class=\"container right\">
        <div class=\"content\">
          <h2>2016</h2>
          <p>Lorem ipsum dolor sit amet, quo ei simul congue exerci, ad nec admodum perfecto mnesarchum, vim ea mazim fierent detracto. Ea quis iuvaret expetendis his, te elit voluptua dignissim per, habeo iusto primis ea eam.</p>
        </div>
      </div>
      <div class=\"container left\">
        <div class=\"content\">
          <h2>2015</h2>
          <p>Lorem ipsum dolor sit amet, quo ei simul congue exerci, ad nec admodum perfecto mnesarchum, vim ea mazim fierent detracto. Ea quis iuvaret expetendis his, te elit voluptua dignissim per, habeo iusto primis ea eam.</p>
        </div>
      </div>
      <div class=\"container right\">
        <div class=\"content\">
          <h2>2012</h2>
          <p>Lorem ipsum dolor sit amet, quo ei simul congue exerci, ad nec admodum perfecto mnesarchum, vim ea mazim fierent detracto. Ea quis iuvaret expetendis his, te elit voluptua dignissim per, habeo iusto primis ea eam.</p>
        </div>
      </div>
      <div class=\"container left\">
        <div class=\"content\">
          <h2>2011</h2>
          <p>Lorem ipsum dolor sit amet, quo ei simul congue exerci, ad nec admodum perfecto mnesarchum, vim ea mazim fierent detracto. Ea quis iuvaret expetendis his, te elit voluptua dignissim per, habeo iusto primis ea eam.</p>
        </div>
      </div>
      <div class=\"container right\">
        <div class=\"content\">
          <h2>2007</h2>
          <p>Lorem ipsum dolor sit amet, quo ei simul congue exerci, ad nec admodum perfecto mnesarchum, vim ea mazim fierent detracto. Ea quis iuvaret expetendis his, te elit voluptua dignissim per, habeo iusto primis ea eam.</p>
        </div>
      </div>
    </div>'''

    # added in v2
    html_pre = '''<div class=\"timeline\">'''
    div_pre = '''<div class=\"container left\"> <div class=\"content\"> <h2>'''
    div_mid = '''</h2> <p>'''
    div_post = '''</p> </div> </div>'''
    html_post = '''</div>'''

    c1_header = ["2010", "2011", "2012", "2013", "2014", "2015", "2016"]
    c1_content = ["malware detected", "user logged in", "network attacked!",
                  "Sample text1", "Sample text 2", "Sample text 3", "Sample text 4"]

    html = html_pre
    for h, c in zip(header, content):
        # h and c might be an integer or date so convert to str
        html += div_pre + str(h) + div_mid + str(c) + div_post
    html += html_post
    # added in v2

    html_body = css + html
    img = demisto.executeCommand("rasterize-email", {"htmlBody": html_body})

    return img


if __name__ in ('__main__', '__builtin__', 'builtins'):
    return_results(timeline(**demisto.args()))
