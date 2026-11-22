# Christmas lights

A Web Bluetooth control page for the Holiday Showhome RGB rope light (controller SL94-6M, FCC ID OXGSL94-6M), which speaks CSRmesh.

Open the GitHub Pages link in the Bluefy browser on iPhone (or Chrome on desktop/Android), close the ShowHome app, tap **Connect to light**, and enter the light's network password under *Setup and testing* once.

Protocol notes: commands are encrypted CSRmesh packets (key = reversed SHA-256 of `PIN + "\0MCP"`, first 16 bytes; AES-128-OFB; truncated HMAC-SHA256), written to characteristics `c4edc000-9daf-11e3-8003/8004-00025b000b00` on service `0xFEF1`. Crypto based on [nkaminski/csrmesh](https://github.com/nkaminski/csrmesh).

## Command format (decoded from a ShowHome app capture)

Plaintext before CSRmesh encryption: `dest(2, LE) 73 B0 00 ff fe B0 P1 P2 P3 00 00`, where `B0 = (counter << 4) | 3` and the counter rolls 0–15.
Observed: `01 01 01` red, `01 02 01` green, `01 00 01` blue, `01 00 03` brightness change, `02 00 03` and `02 1c 03` effects.
Discovery: `00 00 73 (c<<4|e) 00 ff ff 00…` makes each light reply with its name (e.g. `LA7000036DF87`).

`tools/pklg_decode.py` decodes an iOS PacketLogger capture: `python3 tools/pklg_decode.py capture.pklg PIN`.
