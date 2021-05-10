The script is doing the following things:
1. Extract the `index.zip` file from the production public bucket - `marketplace-dist`.
2. Filter new packs since the given date.
3. Retrieve data from the marketplace metadata file for each pack.
4. Build the Slack `blocks` object.
5. Stores in context at the following paths:
    - Pack: a list of dicts, each one with subset of the pack's marketplace metadata file.
    - LastRun: The updated value of the last run, i.e. after new packs calculation.
    - Blocks: The Slack `blocks` object. In case no new packs were found, stores `no new packs`.
     