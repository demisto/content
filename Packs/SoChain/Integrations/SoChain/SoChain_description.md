## SoChain

On-chain data for Bitcoin (BTC), Litecoin (LTC), Dogecoin (DOGE), Zcash (ZEC) and their testnets.

### API key

The key is optional. Without one, lookups are limited to 2,500 a day per IP. A free account gets 75,000 requests a month; paid plans start at $35 a month. Get a key at [https://sochain.com/dashboard](https://sochain.com/dashboard) and enter it in **API Key**. It is sent in the `API-KEY` header.

### Reputation

The `crypto` command never returns a malicious verdict. The DBot score is always 0 (Unknown); its message says whether look-alike addresses sent the address dust (address poisoning), which marks the address as a target, not as a bad actor.