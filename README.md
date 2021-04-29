# Tripwire-Portscan-Honeypot
A Mac OSX suitable portscan honeypot built around Scapy.

## Todo
- Implement ntify
- Make sure the webhooks work
- Make a threshold counter system
- Make a retaliation class
- Make it as light weight a possible and make it in to a runnable background service
- Cleanup the code and refactor classes

## Disclaimer
I just took whatever i could find and slapped it in and made it work. Dont expect to find a finished product or a beautiful symphony of code.
What you will find are ideas could not find with ease. (meaby because it's so simple that nobody even bothered to make it public)

## credits
This project was built around DanaEpp's PortScanHoneypot but makes use of Scapy to make it more suitable for use on MacOS.
The inspiration for this project and credits go to DanaEpp: https://github.com/DanaEpp/ and check out his youtube channel: KnowOps https://www.youtube.com/channel/UC50O6y6u6cij5-0rywXA-Ig

## Usage
Look at the code and make sure it does what it says it does!

pip3 install requirements
configure .conf
sudo python3 tripwire.py
