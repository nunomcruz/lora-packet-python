#!/usr/bin/env python

import sys
from lib.LoraPacket import LoraPacket
from binascii import unhexlify, b2a_hex, a2b_base64

def print_usage_and_exit():
    print("Usage:")
    print("\tlora-packet-decode [--nwkkey <NwkSKey> --appkey <AppSKey> --cntmsb <fCntMSB>] --{hex|base64} <data>")
    sys.exit(1)

def as_hex_string(buffer):
    return b2a_hex(buffer).decode('utf-8').upper()

def as_ascii(hex_str):
    return ''.join(chr(int(x, 16)) if 32 <= int(x, 16) < 127 else '.' for x in (hex_str[i:i+2] for i in range(0, len(hex_str), 2)))

if __name__ == "__main__":
    cmdline_args = sys.argv

    hex_option = cmdline_args.index("--hex") if "--hex" in cmdline_args else -1
    b64_option = cmdline_args.index("--base64") if "--base64" in cmdline_args else -1
    nwk_option = cmdline_args.index("--nwkkey") if "--nwkkey" in cmdline_args else -1
    app_option = cmdline_args.index("--appkey") if "--appkey" in cmdline_args else -1
    fcnt_msb_option = cmdline_args.index("--cntmsb") if "--cntmsb" in cmdline_args else -1

    #if (nwk_option >= 0 and app_option < 0) or (nwk_option < 0 and app_option >= 0):
    #    print_usage_and_exit()

    if hex_option != -1 and hex_option + 1 < len(cmdline_args):
        arg = cmdline_args[hex_option + 1]
        print("decoding from Hex:", arg)
        input_data = unhexlify(arg)
    elif b64_option != -1 and b64_option + 1 < len(cmdline_args):
        arg = cmdline_args[b64_option + 1]
        print("decoding from Base64:", arg)
        input_data = a2b_base64(arg)
    else:
        print_usage_and_exit()

    packet = LoraPacket.from_wire(input_data)

    if nwk_option >= 0 or app_option >= 0:
        fcnt_msb_bytes = [int(cmdline_args[fcnt_msb_option + 1]) & 0xff, int(cmdline_args[fcnt_msb_option + 1]) & 0xff00] if fcnt_msb_option >= 0 else None
    if nwk_option >= 0:
        nwk_key = unhexlify(cmdline_args[nwk_option + 1])
        packet.set_nwk_key(nwk_key)
    if app_option >= 0:
        app_key = unhexlify(cmdline_args[app_option + 1])
        packet.set_app_key(app_key)

    print("Decoded packet")
    print("--------------")
    response = str(packet)

    """
    if nwk_option >= 0 and app_option >= 0:
        fcnt_msb_bytes = [int(cmdline_args[fcnt_msb_option + 1]) & 0xff, int(cmdline_args[fcnt_msb_option + 1]) & 0xff00] if fcnt_msb_option >= 0 else None

        nwk_key = unhexlify(cmdline_args[nwk_option + 1])
        app_key = unhexlify(cmdline_args[app_option + 1])

        mic_ok = " (OK)" if LoraPacket.verify_mic(packet, nwk_key, app_key, fcnt_msb_bytes) else " (BAD != " + as_hex_string(LoraPacket.calculate_mic(packet, nwk_key, app_key, fcnt_msb_bytes)) + ")"

        try:
            plaintext = as_hex_string(LoraPacket.decrypt(packet, app_key, nwk_key, fcnt_msb_bytes))
        except Exception:
            print("Payload Empty")
            plaintext = ""

        #response = response.replace("MIC = [0-9a-fA-F]+", f"$&{mic_ok}")
        response += "MIC = " + mic_ok
        #response = response.replace("FRMPayload = [0-9a-fA-F]+", f"$&\nPlaintext = {plaintext} ('{as_ascii(plaintext)}')")
        response += "\nPlaintext = " + plaintext
    """
    print(response)