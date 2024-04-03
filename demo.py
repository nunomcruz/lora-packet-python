#!/usr/bin/env python

from binascii import unhexlify, hexlify
from lib.LoraPacket import LoraPacket

# Packet decoding
"""
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
"""

# Packet creation
constructed_packet = LoraPacket.from_fields(
    {
        "MType": "Rejoin Request",
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
        "NwkSKey": unhexlify("44024241ed4ce9a68c6a8bc055233fd3"),
        "AppEUI": unhexlify("70B3D57ED00001A6"),
        "DevEUI": unhexlify("0004A30B001A6D4C"),
        "DevNonce": unhexlify("0002"),
        "AppNonce": unhexlify("473F81"),
        "NetID": unhexlify("FF08F5"),
        "DLSettings": unhexlify("23"),
        "RxDelay": unhexlify("01"),
        "CFList": unhexlify("0d3b1c0d3be40d3cac0d3d740d3e3c00"),
        "RejoinType": unhexlify("00"),
        "RJCount0": unhexlify("0000"),
        #"JoinEUI": unhexlify("70B3D57ED00001A6"),
        "NetID": unhexlify("FF08F5"),
    },

)

print("\n\nconstructed_packet.to_string()= \n" + str(constructed_packet) + "\n")

wire_format_packet = constructed_packet.to_bytes()
print("wire_format_packet.to_string()= \n" + hexlify(wire_format_packet).decode() + "\n")
