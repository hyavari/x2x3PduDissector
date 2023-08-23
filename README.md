# x2x3PduDissector
X2/X3 Lawful Interception PDU Wireshark Dissector 

This Lua script is designed to dissect Lawful Interception Protocol (X2/X3 PDU Format)
packets within Wireshark. The script decodes various fields, including version,
PDU type, payload format, payload direction, XID (UUID), correlation ID, and
conditional attributes. It also handles payload interpretation for RTP and SIP
messages. The conditional attributes are dissected as TLVs.

### Purpose:
The purpose of this script is to enhance the analysis of Lawful Interception Protocol
packets by providing a clear representation of the protocol's fields, including their
semantic meanings. It aims to make it easier for analysts to understand and interpret
the captured traffic related to this protocol.

### Usage:
1. Place this script in Wireshark's Plugins directory or load it manually through the
   "Tools > Lua > Evaluate" menu.
2. Once loaded, this script will automatically dissect packets using the "X2X3" protocol.
3. The script provides detailed information about each field within the X2/X3 PDU Format,
   including conditional attributes.

### Note:
- This script is provided as-is and may require updates to match any changes in the
  protocol specification or Wireshark's Lua API.
- For any questions or issues related to the script, please contact me.
