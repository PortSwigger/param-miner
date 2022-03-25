# param-miner

This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.

It combines advanced diffing logic from Backslash Powered Scanner with a binary search technique to guess up to 65,000 param names per request. 
Param names come from a carefully curated built in wordlist, and it also harvests additional words from all in-scope traffic.

To use it, right click on a request in Burp and click "Guess (cookies|headers|params)". 
If you're using Burp Suite Pro, identified parameters will be reported as scanner issues. If not, you can find them listed under Extender->Extensions->Param Miner->Output

You can also launch guessing attacks on multiple selected requests at the same time - this will use a thread pool so you can safely use it on thousands of requests if you want.
Alternatively, you can enable auto-mining of all in scope traffic. Please note that this tool is designed to be highly scalable but may require tuning to avoid performance issues.

For further information, please refer to the whitepapers:

2020: https://portswigger.net/research/web-cache-entanglement

2018: https://portswigger.net/research/practical-web-cache-poisoning

The code can be found at https://github.com/portswigger/param-miner

If you'd like to rate limit your attack, use the Distribute Damage extension.

Contributions and feature requests are welcome.

**Web Cache Entanglement update**

Here's a video of the new features being used to find a fat GET cache poisoning vulnerability in a demo site using Rack::Cache

[![Param Miner demo video](https://img.youtube.com/vi/TQ42N8fqxw4/0.jpg)](https://www.youtube.com/watch?v=TQ42N8fqxw4)

Another video targeting a real site is coming soon - I'm just waiting on the target to patch.

# Changelog
**1.21  2020-09-02**
 - Non-default settings are now highlighted, and can be reset to default
 - Various bugfixes 
 
**1.20  2020-08-05**
 - Major update for Web Cache Entanglement

**1.07 2018-12-06**
 - Fix config window size for small screens (thanks @misoxxx)
 
**1.06 2018-10-10**
 - Support custom wordlists
 - Support fuzz-based detection
 - Numerous bug fixes and quality of life tweaks
 
**1.03 2018-08-09**
 - First public release

# Installation
This extension requires Burp Suite 2021.9 or later. To install it, simply use the BApps tab in Burp.

# Development

Linux: `./gradlew build fatjar`

Windows: `gradlew.bat build fatjar`

Grab the output from `build/libs/param-miner-all.jar`
