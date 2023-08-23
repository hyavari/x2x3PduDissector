# x2x3PduDissector
X2/X3 Lawful Interception PDU Wireshark Dissector 

Welcome to the X2/X3 Lawful Interception PDU Wireshark Dissector! This Lua script is designed to decode Lawful Interception X2 and X3 standards PDU within Wireshark, offering deep insights into each field's semantic meaning. Dive into the world of X2/X3 PDU Format with ease and precision.

## Introduction: Unveiling the Protocol

The Lawful Interception Protocol (X2/X3) plays a crucial role in communication networks, enabling lawful interception for security and monitoring purposes. Analyzing these packets offers invaluable insights into network behavior and potential security vulnerabilities. Also if you are developing IMS/VoLTE/VoNR, 100% you need to provide LI interfaces to related agencies.

## Features and Benefits: Decode with Confidence

- Clear Representation: Our script provides a crystal-clear dissection of X2/X3 packets, including version, PDU type, payload format, payload direction, XID (UUID), correlation ID, and conditional attributes.
- Simplified Analysis: Say goodbye to the complexity of manual decoding. Our script empowers analysts to quickly grasp packet details and potential implications.
- RTP and SIP Interpretation: Seamlessly interpret RTP and SIP messages within the payload, enhancing your understanding of multimedia and communication traffic.

## Usage: Navigating the Script

Place the script in Wireshark's Plugins directory or manually load it via "Tools > Lua > Evaluate."
As soon as it's loaded, our script takes charge, automatically dissecting packets under the "X2X3" protocol.
Witness the magic as each field comes to life, giving you unparalleled insights into the captured traffic.
Interactive Example: Decoding Made Visual

See the power of our script in action:

Encountering issues? We've got you covered:

If you face errors, ensure the script is compatible with the protocol's specifications and Wireshark's Lua API.
Reach out for assistance if you run into any hurdles during your exploration.
Acknowledgments: We're in This Together

A big shoutout to the network analysis community for their inspiration and contributions to enhancing the protocol analysis experience.

For any questions or feedback, feel free to contact me.
