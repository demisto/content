## Generate an Access Token

From the upper-right corner of the Smartsheet screen, click **Account > Personal Settings > API Access** (tab) **> Generate new access token**.

## Important Information
This integration requires the ***smartsheet-sdk***. A new Docker image is needed to package together the ***smartsheet-sdk*** dependencies. You should include the following Python modules as dependencies when creating the Docker Image.
  - enum34
  - requests
  - six
  - python-dateutil
  - sphinx
  - sphinx_rtd_theme
  - setuptools-scm
  - gitchangelog mako
  - collective.checkdocs
 
 For any questions, reach out to the #demisto-developers channel on the DFIR Community on Slack (https://dfircommunity.slack.com)
