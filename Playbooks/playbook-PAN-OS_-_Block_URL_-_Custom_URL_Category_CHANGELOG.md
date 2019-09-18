## [Unreleased]


## [19.9.1] - 2019-09-18
#### New Playbook
This playbook blocks URLs using Palo Alto Networks Panorama or Firewall through Custom URL Categories.
The playbook checks whether the input URL category already exists, and if the URLs are a part of this category. Otherwise, it will create the category, block the URLs, and commit the configuration.