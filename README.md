# param-miner

This extension identifies hidden, unlinked parameters. It's particularly useful for finding web cache poisoning vulnerabilities.

It combines advanced diffing logic from Backslash Powered Scanner with a binary search technique to guess up to 65,000 param names per request. 
Param names come from a carefully curated built in wordlist, and it also harvests additional words from all in-scope traffic.

To use it, right click on a request in Burp and click "Guess (cookies|headers|params)". 
If you're using Burp Suite Pro, identified parameters will be reported as scanner issues. If not, you can find them listed under Extender->Extensions->Param Miner->Output

You can also launch guessing attacks on multiple selected requests at the same time - this will use a thread pool so you can safely use it on thousands of requests if you want.
Alternatively, you can enable auto-mining of all in scope traffic. Please note that this tool is designed to be highly scalable but may require tuning to avoid performance issues.

For further information, please refer to the whitepaper at https://portswigger.net/blog/practical-web-cache-poisoning

The code can be found at https://github.com/portswigger/param-miner

Contributions and feature requests are welcome.

# Changelog
 
**1.03 20180809**
 - First public release

# Installation
This extension requires Burp Suite Pro 1.7.10 or later. To install it, simply use the BApps tab in Burp.

