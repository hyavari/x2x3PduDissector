# x2x3PduDissector

Wireshark Lua dissector for X2/X3 Lawful Interception PDU format (ETSI TS 103 221-2).

If you're working on IMS/VoLTE/VoNR, you'll likely need LI interfaces at some point. This dissector makes debugging those a lot easier.

## Features

- Decodes all X2/X3 header fields: version, PDU type, payload format, payload direction, XID (UUID), correlation ID
- Parses conditional attributes (TLV format): timestamps, IPs, ports, sequence numbers, etc.
- Hands off RTP and SIP payloads to Wireshark's built-in dissectors
- Handles TCP reassembly for split PDUs

## Installation

Copy `x2x3PduDissector.lua` to your Wireshark plugins folder:

- **Linux**: `~/.local/lib/wireshark/plugins/`
- **macOS**: `~/.local/lib/wireshark/plugins/` or `/Applications/Wireshark.app/Contents/PlugIns/wireshark/`
- **Windows**: `%APPDATA%\Wireshark\plugins\`

Or load it manually: **Tools → Lua → Evaluate**

## Usage

Once loaded, apply "X2X3" as a filter or right-click a packet and select **Decode As → X2X3**.

The dissector registers on TCP/UDP port 0 by default - you may want to edit the last lines to specify your actual LI ports.

## Screenshots

![image](https://github.com/hyavari/x2x3PduDissector/assets/10007189/c1533013-2319-48f5-b2a7-3026cb6faf36)

![image](https://github.com/hyavari/x2x3PduDissector/assets/10007189/198d32bd-017e-489e-9c19-0ea0a5585637)

## Troubleshooting

- Make sure you're running a recent Wireshark version with Lua support enabled
- Check **Tools → Lua → Console** for any script errors
- If packets aren't being decoded, verify the port registration at the bottom of the script

## Questions?

Open an issue or reach out via email.
