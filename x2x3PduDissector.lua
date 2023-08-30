--[[
Author: Hossein Yavari
Email: hyavari26 [at] gmail [dot] com
Date: 2023-08-22
Version: 1.0.0

Description:
This Lua script is designed to dissect Lawful Interception Protocol (X2/X3 PDU Format)
packets within Wireshark. The script decodes various fields, including version,
PDU type, payload format, payload direction, XID (UUID), correlation ID, and
conditional attributes. It also handles payload interpretation for RTP and SIP
messages. The conditional attributes are dissected as TLVs.

Purpose:
The purpose of this script is to enhance the analysis of Lawful Interception Protocol
packets by providing a clear representation of the protocol's fields, including their
semantic meanings. It aims to make it easier for analysts to understand and interpret
the captured traffic related to this protocol.

Usage:
1. Place this script in Wireshark's Plugins directory or load it manually through the
   "Tools > Lua > Evaluate" menu.
2. Once loaded, this script will automatically dissect packets using the "X2X3" protocol.
3. The script provides detailed information about each field within the X2/X3 PDU Format,
   including conditional attributes.

Note:
- This script is provided as-is and may require updates to match any changes in the
  protocol specification or Wireshark's Lua API.
- For any questions or issues related to the script, please contact the author via email.
--]]

-- Define the protocol
X2X3_protocol = Proto("X2X3", "X2/X3 Lawful Interception PDU")

-- Define the fields
local fields = {
    version = ProtoField.uint16("x2x3.version", "Version", base.HEX),
    pduType = ProtoField.uint16("x2x3.pduType", "PDU Type", base.DEC),
    headerLength = ProtoField.uint32("x2x3.headerLength", "Header Length", base.DEC),
    payloadLength = ProtoField.uint32("x2x3.payloadLength", "Payload Length", base.DEC),
    payloadFormat = ProtoField.uint16("x2x3.payloadFormat", "Payload Format", base.DEC),
    payloadDirection = ProtoField.uint16("x2x3.payloadDirection", "Payload Direction", base.DEC),
    xid = ProtoField.guid("x2x3.xid", "XID (UUID)"),
    correlationId = ProtoField.string("x2x3.correlationId", "Correlation ID"),
    payload = ProtoField.bytes("x2x3.payload", "Payload")
}

X2X3_protocol.fields = fields

local pduTypesMap = {
    [1] = "X2",
    [2] = "X3",
    [3] = "Keepalive",
    [4] = "Keepalive Acknowledgement"
}

local payloadTypesMap = {
    [0] = "Keepalive",
    [1] = "ETSI TS 102 232-1",
    [2] = "3GPP TS 33.128",
    [3] = "ETSI TS 133 108",
    [4] = "Proprietary Payload",
    [5] = "IPv4 Packet",
    [6] = "IPv6 Packet",
    [7] = "Ethernet Frame",
    [8] = "RTP Packet",
    [9] = "SIP Message",
    [10] = "DHCP Message",
    [11] = "RADIUS Packet",
    [12] = "GTP-U Message",
    [13] = "MSRP Message",
}

local payloadDirectionMap = {
    [0] = "Keepalive",
    [1] = "Unknown",
    [2] = "Sent to the target",
    [3] = "Sent from the target",
    [4] = "Multiple direction",
    [5] = "Not applicable",
}

local attributeTypesMap = {
    [1] = "ETSI TS 102 232-1",
    [2] = "3GPP TS 33.128",
    [3] = "ETSI TS 133 108",
    [4] = "Proprietary Attribute",
    [5] = "Domain ID (DID)",
    [6] = "Network Function ID (NFID)",
    [7] = "Interception Point ID (IPID)",
    [8] = "Sequence Number",
    [9] = "Timestamp",
    [10] = "Source IPv4 address",
    [11] = "Destination IPv4 address",
    [12] = "Source IPv6 address",
    [13] = "Destination IPv6 address",
    [14] = "Source Port",
    [15] = "Destination Port",
    [16] = "IP Protocol",
    [17] = "Matched Target Identifier",
    [18] = "Other Target Identifier",
}

local ipProtocolsMap = {
    [6] = "TCP",
    [17] = "UDP",
}

-- Define the dissector function for conditional attributes
local function conditional_attributes_dissector(buffer, pinfo, tree)
    local offset = 0
    local subtree = tree:add(X2X3_protocol, buffer(), "Conditional Attributes")

    while offset < buffer:len() do
        local attribute_type = buffer(offset, 2):uint()
        local attribute_length = buffer(offset + 2, 2):uint()

        local attribute_tree = subtree:add(buffer(offset, attribute_length + 4), attributeTypesMap[attribute_type])
        attribute_tree:add(attribute_type, buffer(offset, 2)):append_text(" (Type)")
        attribute_tree:add(attribute_length, buffer(offset + 2, 2)):append_text(string.format(
            " bytes"))

        local attribute_value = buffer(offset + 4, attribute_length):string()

        if attribute_type == 14 or attribute_type == 15 then
            attribute_value = buffer(offset + 4, attribute_length):uint()
            attribute_tree:add(attribute_value, buffer(offset + 4, attribute_length)):append_text(" (Value)")
        elseif attribute_type == 9 then
            local seconds = buffer(offset + 4, 4):uint()
            local nanoseconds = buffer(offset + 8, 4):uint()
            local timestamp_value = seconds + nanoseconds * 1e-9
            local formatted_timestamp = os.date("%Y-%m-%d %H:%M:%S", timestamp_value)
            attribute_tree:add(formatted_timestamp, buffer(offset + 4, attribute_length - 4))
                :append_text(" (Value)")
        elseif attribute_type == 16 then
            attribute_tree:add(ipProtocolsMap[buffer(offset + 4, attribute_length):uint()],
                buffer(offset + 4, attribute_length)):append_text(" (Value)")
        elseif attribute_type == 12 or attribute_type == 13 then
            attribute_value = buffer(offset + 4, attribute_length)
            attribute_tree:add("Value", attribute_value):set_text(string.format("%s (Value)",
                attribute_value:ipv6()))
        elseif attribute_type == 10 or attribute_type == 11 then
            attribute_value = buffer(offset + 4, attribute_length)
            attribute_tree:add("Value", attribute_value):set_text(string.format(" %s (Value)",
                attribute_value:ipv4()))
        else
            attribute_tree:add(attribute_value, buffer(offset + 4, attribute_length)):append_text(" (Value)")
        end

        offset = offset + 4 + attribute_length
    end
end

-- Dissector function
function X2X3_protocol.dissector(buffer, pinfo, tree)
    -- Check if the buffer length is valid
    if not buffer:len() then
        return
    end

    -- TCP reassemble issue
    if buffer(8, 4):uint() > buffer:len() - buffer(4, 4):uint() then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
        return
    end

    -- TODO: need to hanle merged PDUs, not decode for now!
    if buffer:len() > buffer(4, 4):uint() + buffer(8, 4):uint() then
        return
    end

    -- Perform sanity check on header values
    local pduType = buffer(2, 2):uint()
    if not pduTypesMap[pduType] then
        return
    end

    local subtree = tree:add(X2X3_protocol, buffer())
    local headerSubtree = subtree:add(X2X3_protocol, buffer(), "Headers")
    local payloadSubtree = subtree:add(X2X3_protocol, buffer(), "Payload")

    -- Add version
    local version_value = buffer(0, 2):uint()
    local major = bit32.rshift(version_value, 8)
    local minor = bit32.band(version_value, 0xFF)
    local version_text = string.format("Version: Major: %d, Minor: %d", major, minor)
    headerSubtree:add(fields.version, buffer(0, 2)):set_text(version_text)

    -- Add pduType
    headerSubtree:add(fields.pduType, buffer(2, 2)):append_text(string.format(" (%s)", pduTypesMap[pduType]))
    -- More readable output
    if pduType == 3 or pduType == 4 then
        pinfo.cols.info:set(pduTypesMap[pduType])
    end

    -- Add headerLength
    local headerLength = buffer(4, 4):uint()
    headerSubtree:add(fields.headerLength, buffer(4, 4)):append_text(string.format(" bytes"))

    -- Add payloadLength
    headerSubtree:add(fields.payloadLength, buffer(8, 4)):append_text(string.format(" bytes"))

    -- Add payloadFormat
    local payloadFormat = buffer(12, 2):uint()
    headerSubtree:add(fields.payloadFormat, buffer(12, 2)):append_text(string.format(" (%s)", payloadTypesMap
        [buffer(12, 2):uint()]))

    -- Add payloadDirection
    headerSubtree:add(fields.payloadDirection, buffer(14, 2)):append_text(string.format(" (%s)",
        payloadDirectionMap[buffer(14, 2):uint()]))

    -- Add xid
    headerSubtree:add(fields.xid, buffer(16, 16))

    -- Add correlationId
    headerSubtree:add(fields.correlationId, buffer(32, 8))

    -- Add conditional attributes
    conditional_attributes_dissector(buffer(40, headerLength - 40), pinfo, headerSubtree)

    -- Add payload field
    if payloadFormat == 0 then
        payloadSubtree:add("nil", buffer(headerLength, buffer:len() - headerLength)):append_text(" (Keepalive)")
        -- Check if the payload format is RTP (8) or SIP Message (9)
    elseif payloadFormat == 8 then
        -- Call the RTP dissector for the payload
        local rtp_dissector = Dissector.get("rtp")
        rtp_dissector:call(buffer(headerLength, buffer:len() - headerLength):tvb(), pinfo, payloadSubtree)
    elseif payloadFormat == 9 then
        -- Call the SIP dissector for the payload
        local sip_dissector = Dissector.get("sip")
        sip_dissector:call(buffer(headerLength, buffer:len() - headerLength):tvb(), pinfo, payloadSubtree)
    else
        -- Handle other payload formats or display as raw data
        payloadSubtree:add(fields.payload, buffer(headerLength, buffer:len() - headerLength)):append_text(" (Raw data)")
    end

    -- Set the protocol name in the packet details
    pinfo.cols.protocol = X2X3_protocol.name
end

-- Register the dissector
DissectorTable.get("tcp.port"):add(0, X2X3_protocol)
DissectorTable.get("udp.port"):add(0, X2X3_protocol)
