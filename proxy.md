

Param Miner has a feature called "Identify proxyable destinations". 
This can lead to high-impact discoveries, such as systems that are meant to be internal-only.

It will work out of the box, but a little configuration will make it a lot more powerful.

- Tick `external subdomain lookup` to dynmically look up known subdomains using columbus.elmasy.com. Warning: this discloses the top-level private domain that you are targeting. That's why it's not enabled by default.
- Use `subdomains-generic` to specify the path to your own subdomain wordlist. Download them from sources like: https://wordlists.assetnote.io/ and https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
- Use `subdomains-specific` to specify a folder blah 
  





For further information, please refer to https://portswigger.net/research/listen-to-the-whispers