

Param Miner has a feature called "Identify proxyable destinations". 
This can lead to high-impact discoveries, such as systems that are meant to be internal-only.

It will work out of the box, but a little configuration will make it a lot more powerful:

Exploring known subdomains (highly recommended)
- Tick `external subdomain lookup` to dynamically look up known subdomains using ip.thc.org. Warning: this discloses the top-level private domain that you are targeting. For example, if you target `beta.api.example.com`, Elmasy will see `example.com` in their server logs. That's why it's not enabled by default.
- If you have an alternative source of subdomains from your own recon, you can integrate these by placing them into a folder in the format /folder/top-level-domain, and using the `subdomains-specific` setting to load it. For example, if you set the path to `/hostnames/$domain` and scan `proxy.example.com`, Param Miner will load domains from `/hostnames/example.com`

Additional hostname wordlists:  
- Use `subdomains-generic` to specify the path to your own subdomain wordlist. Download them from sources like: https://wordlists.assetnote.io/ and https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

For further information, please refer to https://portswigger.net/research/listen-to-the-whispers

If it still makes no sense, please let me know - I want people to get the most out of this tool!
