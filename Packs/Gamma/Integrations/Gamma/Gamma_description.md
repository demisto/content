#### API Key
An API Key from your Gamma instance is required. 
If you do not have a key, you can obtain one by going to your Gamma instance > Settings > API Key and generating a key.

#### Fetching
1. If you are fetching violations, ensure that 'Fetches incidents' is selected.
2. Enter the Gamma violation ID number at which to begin your fetch. The fetch is inclusive of the ID you enter. If empty, the fetch will default to the first violation that exists. You can retrieve a list of violation IDs by running the gamma-get-violation-list command.
3. You may enter an optional limit of violations to fetch at once for 'Results per fetch'.