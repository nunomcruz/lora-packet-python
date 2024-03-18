#!/usr/bin/env python

import sys
from lib.LoraPacket import LoraPacket
from binascii import unhexlify, hexlify

# Packet decoding
packet = LoraPacket.from_wire(unhexlify("40F17DBE4900020001954378762B11FF0D"))

print("packet.to_string()=\n" + str(packet))

print("packet MIC=" + hexlify(packet.MIC).decode())
print("FRMPayload=" + hexlify(packet.FRMPayload).decode())

NwkSKey = unhexlify("44024241ed4ce9a68c6a8bc055233fd3")
print("MIC check=" + ("OK" if LoraPacket.verify_mic(packet, NwkSKey) else "fail"))

print("calculated MIC=" + hexlify(LoraPacket.calculate_mic(packet, NwkSKey)).decode())

AppSKey = unhexlify("ec925802ae430ca77fd3dd73cb2cc588")
print("Decrypted (ASCII)='" + packet.decrypt().decode() + "'")
print("Decrypted (hex)='0x" + hexlify(packet.decrypt()).decode() + "'")

# Packet creation
constructed_packet = LoraPacket.from_fields(
    {
        "MType": "Unconfirmed Data Up",
        "DevAddr": unhexlify("01020304"),
        "FCtrl": {
            "ADR": False,
            "ACK": True,
            "ADRACKReq": False,
            "FPending": False,
        },
        "FCnt": unhexlify("0003"),
        "payload": "test",
        "AppSKey": unhexlify("ec925802ae430ca77fd3dd73cb2cc588"),
        "NwkSKey": unhexlify("44024241ed4ce9a68c6a8bc055233fd3")
    },

)

print("constructed_packet.to_string()=\n" + str(constructed_packet))

wire_format_packet = constructed_packet.get_phy_payload()
print("wire_format_packet.to_string()=\n" + hexlify(wire_format_packet).decode())