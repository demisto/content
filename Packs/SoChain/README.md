Enrich cryptocurrency addresses and transactions in Bitcoin (BTC), Litecoin (LTC), Dogecoin (DOGE) and Zcash (ZEC) investigations, such as ransomware, extortion and fraud, with on-chain data from [SoChain](https://sochain.com).

## What does this pack do?

- Runs the `crypto` reputation command on Cryptocurrency indicators, adding the address's network, balances, transaction counts and first and last activity.
- Checks whether an address was targeted by address poisoning: look-alike addresses that sent it dust, imitating an address it really paid or was paid by.
- Gets a transaction with every input and output.
- Lists who an address paid and was paid by lately.
- Works without an API key (2,500 lookups a day per IP); a key from the [SoChain dashboard](https://sochain.com/dashboard) raises the limit.

SoChain gives on-chain facts, not verdicts: the DBot score it returns is always 0 (Unknown).
