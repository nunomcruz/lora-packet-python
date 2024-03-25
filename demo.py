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
packet.set_nwk_key(NwkSKey)
print("MIC check=" + ("OK" if packet.verify_mic() else "fail"))

print("Calculated MIC=" + hexlify(packet.calculate_mic()).decode())

AppSKey = unhexlify("ec925802ae430ca77fd3dd73cb2cc588")
packet.set_app_key(AppSKey)
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
        "Payload": "test",
        "AppSKey": unhexlify("ec925802ae430ca77fd3dd73cb2cc588"),
        "NwkSKey": unhexlify("44024241ed4ce9a68c6a8bc055233fd3")
    },

)

print("constructed_packet.to_string()= " + str(constructed_packet) + "\n")

wire_format_packet = constructed_packet.to_bytes()
print("wire_format_packet.to_string()= " + hexlify(wire_format_packet).decode() + "\n")