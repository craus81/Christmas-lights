# Christmas lights

A Web Bluetooth control page for the Holiday Showhome RGB rope light (controller SL94-6M, FCC ID OXGSL94-6M), which speaks CSRmesh.

Open the GitHub Pages link in the Bluefy browser on iPhone (or Chrome on desktop/Android), close the ShowHome app, tap **Connect to light**, and enter the light's network password under *Setup and testing* once.

Protocol notes: commands are encrypted CSRmesh packets (key = reversed SHA-256 of `PIN + "\0MCP"`, first 16 bytes; AES-128-OFB; truncated HMAC-SHA256), written to characteristics `c4edc000-9daf-11e3-8003/8004-00025b000b00` on service `0xFEF1`. Crypto based on [nkaminski/csrmesh](https://github.com/nkaminski/csrmesh).
