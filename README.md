# This is a port of the original lora-packet library to Python

The original excellent work by Antony Kirby can be found here [LoRA Packet](https://github.com/anthonykirby/lora-packet).

Following is the adaptation of the original README.md file.

# lora-packet-python

A pure [python](http://python.org/) library to decode and encode packets
for LoRa/LoRaWAN<sup>TM</sup> radio communication, based on the specification
from the [LoRa Alliance](https://www.lora-alliance.org/) (based on V1.0.2 final), and as used by [The Things Network](https://www.thethingsnetwork.org/).

Packet decoding is also wrapped in a simple command-line tool that accepts input in hex and base-64

## Why?

- LoRa packets are encrypted at the radio link level. They could be
  decrypted at the radio receiver, but frequently they're transferred onwards
  as-is, because the radio doesn't have the crypto keys. This library lets you
  handle them in your code, rather than relying on less transparent / less
  documented / less convenient libraries / modules / systems.
- as a debugging tool, to check and decrypt packets
- python is available both on the application server, and can also be
  available on network gateways (which are otherwise hard to write code to
  run on)- a single library can be used in both places / either place
- inverted use case: you have a remote gateway, and you want to send gateway
  telemetry/monitoring using the same uplink channel as used by the radio, as
  LoRa packets - so you encode your gateway telemetry as LoRa packets & slip
  them into the uplink.

## Features:

- LoRa packet parsing & analysis
- MIC (Message Integrity Check) checking
- payload decryption
- decodes uplink & downlink packets, network join etc
- ability to create LoRa format packets

## Installation

Add lib folder to your project and import LoraPacket.

## Usage (command-line packet decoding):

```
$ cli.py --hex 40F17DBE4900020001954378762B11FF0D
```

```
$ cli.py --base64 QPF9vkkAAgABlUN4disR/w0=
```

```
$ cli.py \
        --appkey ec925802ae430ca77fd3dd73cb2cc588 \
        --nwkkey 44024241ed4ce9a68c6a8bc055233fd3 \
        --hex 40F17DBE4900020001954378762B11FF0D
```

## Usage (packet decoding from wire):

### from_wire(buffer)

Parse & create packet structure from wire-format buffer (i.e. "radio PHYPayload")

### packet.get_fields()

returns an object containing the decoded packet fields, named as per
LoRa spec, e.g. _MHDR_, _MACPayload_ etc

Note: _DevAddr_ and _FCnt_ are stored big-endian, i.e. the way round
that you'd expect to see them, not how they're sent down the wire.

### packet.get_mtype()

returns the packet _MType_ as a string (e.g. "Unconfirmed Data Up")

### packet.get_dir()

returns the direction (_Dir_) as a string ('up' or 'down')

### packet.get_fcnt()

returns the frame count (_FCnt_) as a number

### packet.is_confirmed()

returns true if packet is confirmed, else returns false

### packet.get_fport()

returns the port (_FPort_) as a number (or null if FPort is absent)

### packet.get_fctrl_ack()

returns the flag (_ACK_) of field _FCtrl_ as a boolean

### packet.get_fctrl_fpending()

returns the flag (_FPending_) of field _FCtrl_ as a boolean

### packet.get_fctrl_adr()

returns the flag (_ADR_) of field _FCtrl_ as a boolean

### packet.get_fctrl_adrackreq()

returns the flag (_ADRACKReq_) of field _FCtrl_ as a boolean

### packet.encrypt_fopts(NwkSEncKey, [, SNwkSIntKey] [, FCntMSBytes] [, ConfFCntDownTxDrTxCh])
returns an object containing the encrypted FOpts field.
If SNwkSIntKey is provided, the mic is recalculated and modifies the packet.

### packet.decrypt_fopts(NwkSEncKey, [, SNwkSIntKey] [, FCntMSBytes] [, ConfFCntDownTxDrTxCh])
alias for encryptFOpts, just for sake of clarification

### packet.verify_mic([FCntMSBytes])

returns a boolean; true if the MIC is correct (i.e. the value at the end of
the packet data matches the calculation over the packet contents)

NB AppKey is used for Join Request/Accept, otherwise NwkSkey is used

Optionally, if using 32-byt FCnts, supply the upper 2 bytes as a Buffer.

### packet.calculate_mic([FCntMSBytes])

returns the MIC, as a buffer

NB AppKey is used for Join Request/Accept, otherwise NwkSkey is used

Optionally, if using 32-byt FCnts, supply the upper 2 bytes as a Buffer.

### packet.recalculate_mic([FCntMSBytes])

calculates the MIC & updates the packet (no return value)

NB AppKey is used for Join Request/Accept, otherwise NwkSkey is used

Optionally, if using 32-byt FCnts, supply the upper 2 bytes as a Buffer.

### packet.decrypt([FCntMSBytes]

decrypts and returns the payload as a buffer:
The library cannot know whether this is an ASCII string or binary data,
so you will need to interpret it appropriately.

NB the relevant key is chosen depending on the value of _FPort_,
and NB key order is different than MIC APIs

### packet.decrypt_join_accept()

decrypts and returns the Join Accept Message as a buffer:

```javascript
packet = LoraPacket.from_wire(unhexlify("40F17DBE4900020001954378762B11FF0D"))
```

## Usage (packet encoding to wire):

### from_fields(data)

takes an object with properties representing fields in the packet - see example below

- and generates a valid packet from them. If a NwkSKey is provided then the
  MIC is calculated (otherwise = "EEEEEEEE") and if the relevant encryption key
  (AppSKey or NwkSKey depending on port) then the payload is encrypted.

The wire-format payload can be obtained by calling _to_wire()_
(or _get_fields().PHYPayload_)


#### Required fields:

- _MType_ - supplied as number (0-7 or constants) or string
- _DevAddr_ - supplied as Buffer (4)
- _FCnt_ - supplied as number or Buffer(2)

#### Optional fields:

- _FCtrl.ADR_ - boolean (default = false)
- _FCtrl.ADRACKReq_ - boolean (default = false)
- _FCtrl.ACK_ - boolean (default = false)
- _FCtrl.FPending_ - boolean (default = false)
- _FPort_ - number (default = 1)

#### Lorawan 1.1
 in Lorawan 1.1 optional fields after `data` are:
- NwkSEncKey,
- SNwkSIntKey,
- FNwkSIntKey,
- FCntMSBytes
- ConfFCntDownTxDrTxCh

For usage Refer to Lorawan 1.1 Spec.

## Example:

```python
from binascii import unhexlify, hexlify
from lib.LoraPacket import LoraPacket

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
    },

)

print("\n\nconstructed_packet.to_string()= \n" + str(constructed_packet) + "\n")

wire_format_packet = constructed_packet.to_bytes()
print("wire_format_packet.to_string()= \n" + hexlify(wire_format_packet).decode() + "\n")
```


## Notes:

#### Online Decoder

There's a nice [online decoder that uses this library](https://runkit.io/avbentem/lorawan-packet-decoder/branches/master).

NB this is created & maintained by a third party & I can't support or answer questions about it.

#### Endianness

- LoRa sends data over the wire in little-endian format
  (see spec #1.2 "The octet order for all multi-­octet fields is little endian")
- lora-packet attempts to hide this from you, so e.g. DevAddr & FCnt are
  presented in big-endian format.
- For example, DevAddr=49be7df1 is sent over the wire as 0xf1, 0x7d, 0xbe, 0x49.
- Similarly, the fields in the Join Request message (AppEUI, DevEUI, DevNonce)
  are reversed on the wire

#### Can I help?

- I've done some testing, but of course I can only test using the packets
  that I can generate & receive with the radios I've got, and packets I've
  constructed myself. If you find a packet that `lora-packet` fails to parse,
  or incorrectly decodes / decrypts etc, please let me know!

#### LoRaWAN - naming clarification

It took me longer than expected to understand the various IDs & key names.
Different terminology is used by LoRaWAN / TTN / Multitech, & there's both
OTA & manual personalisation options. This is a quick summary which I hope
you'll find helpful.

(TODO!)

#### Version history

- 0.0.1 - initial release based on lora-packet node.js 0.9.0


#### TODO

- MAC Commands, as sent in _FOpts_ (or piggybacked in _FRMPayload_)

#### Credits
- Thank you to [Antony Kirby](https://github.com/anthonykirby) for the original [lora-packet](https://github.com/anthonykirby/lora-packet) library
- Thank you to [David Olivari](https://github.com/davidonet)
- Thank you to [Larko](https://github.com/larkolab)
- Thank you to [Tommas Bakker](https://github.com/tommas-factorylab)
- Thank you to [Rob Gillan](https://github.com/rgillan)
- Thank you to [Christopher Hunt](https://github.com/huntc)
- Thank you to [Thibault Ortiz](https://github.com/tortizactility)
- Thank you to [Flemming Madsen](https://github.com/amplexdenmark)
- Thank you to [Giorgio Pillon](https://github.com/kalik1)
- Thank you to [Nuno Cruz](https://github.com/nunomcruz)
- Thank you to [Felipe Lima](https://github.com/felipefdl) and the fine folks at [TagoIO](https://tago.io/)
- Thank you to [Nicolas Graziano](https://github.com/ngraziano)
- Thank you to [Benjamin Cabé](https://github.com/kartben)
- Thank you to [kalik1](https://github.com/kalik1)
- Thank you to [Pierre PLR](https://github.com/pplr)
- Thank you to [Ricardo Stoklosa](https://github.com/RicardoStoklosa)
- Thank you to [Lucas](https://github.com/aqllmcdavid)

