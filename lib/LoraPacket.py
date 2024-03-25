from enum import Enum
from binascii import unhexlify, hexlify
import typing
from typing import NamedTuple
from typing import Dict
from typing import Union
from typing import Optional
from dataclasses import dataclass
import json
from lib.utils import *
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

class MTypeEnum(Enum):
    JOIN_REQUEST = 0
    JOIN_ACCEPT = 1
    UNCONFIRMED_DATA_UP = 2
    UNCONFIRMED_DATA_DOWN = 3
    CONFIRMED_DATA_UP = 4
    CONFIRMED_DATA_DOWN = 5
    REJOIN_REQUEST = 6

MTYPE_DESCRIPTIONS = {
    MTypeEnum.JOIN_REQUEST: "Join Request",
    MTypeEnum.JOIN_ACCEPT: "Join Accept",
    MTypeEnum.UNCONFIRMED_DATA_UP: "Unconfirmed Data Up",
    MTypeEnum.UNCONFIRMED_DATA_DOWN: "Unconfirmed Data Down",
    MTypeEnum.CONFIRMED_DATA_UP: "Confirmed Data Up",
    MTypeEnum.CONFIRMED_DATA_DOWN: "Confirmed Data Down",
    MTypeEnum.REJOIN_REQUEST: "Rejoin Request",
}

DESCRIPTIONS_MTYPE = {v: k for k, v in MTYPE_DESCRIPTIONS.items()} # reverse dict


class Range(NamedTuple):
    start: int
    end: int

PacketStructure = Dict[str, Dict[str, Range]]

PACKET_STRUCTURES: PacketStructure = {
    "JOIN_REQUEST": {
        "AppEUI": Range(start=1, end=9),
        "DevEUI": Range(start=9, end=17),
        "DevNonce": Range(start=17, end=19),
    },
    "JOIN_ACCEPT": {
        "AppNonce": Range(start=1, end=4),
        "NetID": Range(start=4, end=7),
        "DevAddr": Range(start=7, end=11),
        "DLSettings": Range(start=11, end=12),
        "RxDelay": Range(start=12, end=13),
    },
    "REJOIN_TYPE_1": {
        "NetID": Range(start=2, end=5 ),
        "DevEUI": Range(start=5, end=13 ),
        "RJCount0": Range(start=13, end=15 ),
    },
    "REJOIN_TYPE_2": {
        "JoinEUI": Range(start=2, end=10 ),
        "DevEUI": Range(start=10, end=18 ),
        "RJCount1": Range(start=13, end=15 ),
    },
}

class LoRaWANVersion(str, Enum):
    V1_0 = "1.0"
    V1_1 = "1.1"

class Masks(Enum):
    FCTRL_ADR = 0x80
    FCTRL_ADRACKREQ = 0x40
    FCTRL_ACK = 0x20
    FCTRL_FPENDING = 0x10

    DLSETTINGS_RXONEDROFFSET_MASK = 0x70
    DLSETTINGS_RXONEDROFFSET_POS = 4
    DLSETTINGS_RXTWODATARATE_MASK = 0x0f
    DLSETTINGS_RXTWODATARATE_POS = 0
    DLSETTINGS_OPTNEG_MASK = 0x80
    DLSETTINGS_OPTNEG_POS = 7

    RXDELAY_DEL_MASK = 0x0f
    RXDELAY_DEL_POS = 0

class UserFields(Dict[str, Union[bytes, int, Dict[str, bool]]]):
    def __init__(
        self,
        CFList: Optional[bytes] = None,
        RxDelay: Optional[Union[bytes, int]] = None,
        DLSettings: Optional[Union[bytes, int]] = None,
        NetID: Optional[bytes] = None,
        AppNonce: Optional[bytes] = None,
        DevNonce: Optional[bytes] = None,
        DevEUI: Optional[bytes] = None,
        AppEUI: Optional[bytes] = None,
        FPort: Optional[int] = None,
        FOpts: Optional[Union[bytes, str]] = None,
        FCnt: Optional[Union[bytes, int]] = None,
        MType: Optional[Union[bytes, int, str]] = None,
        DevAddr: Optional[bytes] = None,
        Payload: Optional[Union[bytes, str]] = None,
        FCtrl: Optional[Dict[str, bool]] = None,
        JoinReqType: Optional[Union[bytes, int]] = None,
        AppSKey: Optional[bytes] = None,
        NwkSKey: Optional[bytes] = None
    ):
        super().__init__()
        self["CFList"] = CFList
        self["RxDelay"] = RxDelay
        self["DLSettings"] = DLSettings
        self["NetID"] = NetID
        self["AppNonce"] = AppNonce
        self["DevNonce"] = DevNonce
        self["DevEUI"] = DevEUI
        self["AppEUI"] = AppEUI
        self["FPort"] = FPort
        self["FOpts"] = FOpts
        self["FCnt"] = FCnt
        self["MType"] = MType
        self["DevAddr"] = DevAddr
        self["Payload"] = Payload
        self["FCtrl"] = FCtrl
        self["JoinReqType"] = JoinReqType
        self["AppSKey"] = AppSKey
        self["NwkSKey"] = NwkSKey
        self._standardize()

    def _standardize(self):
        if isinstance(self["RxDelay"], int):
            self["RxDelay"] = bytes([self["RxDelay"]])
        if isinstance(self["DLSettings"], int):
            self["DLSettings"] = bytes([self["DLSettings"]])
        if isinstance(self["JoinReqType"], int):
            self["JoinReqType"] = bytes([self["JoinReqType"]])
        if isinstance(self["FCnt"], int):
            self["FCnt"] = bytes([self["FCnt"]])
        if isinstance(self["MType"], int):
            self["MType"] = bytes([self["MType"]])
        if isinstance(self["FOpts"], str):
            self["FOpts"] = unhexlify(self["FOpts"])
        if isinstance(self["Payload"], str):
            #self["Payload"] = unhexlify(self["Payload"])
            self["Payload"] = self["Payload"].encode()
        if isinstance(self["CFList"], str):
            self["CFList"] = unhexlify(self["CFList"])
        if isinstance(self["DevEUI"], str):
            self["DevEUI"] = unhexlify(self["DevEUI"])
        if isinstance(self["AppEUI"], str):
            self["AppEUI"] = unhexlify(self["AppEUI"])
        if isinstance(self["DevAddr"], str):
            self["DevAddr"] = unhexlify(self["DevAddr"])
        if isinstance(self["NetID"], str):
            self["NetID"] = unhexlify(self["NetID"])
        if isinstance(self["AppNonce"], str):
            self["AppNonce"] = unhexlify(self["AppNonce"])
        if isinstance(self["DevNonce"], str):
            self["DevNonce"] = unhexlify(self["DevNonce"])
        if isinstance(self["FCtrl"], dict):
            self["FCtrl"] = {k: bool(v) for k, v in self["FCtrl"].items()}

    @property
    def CFList(self) -> Optional[bytes]:
        return self.get("CFList")

    @CFList.setter
    def CFList(self, value: Optional[bytes]):
        self["CFList"] = value

    @property
    def RxDelay(self) -> Optional[Union[bytes, int]]:
        return self.get("RxDelay")

    @RxDelay.setter
    def RxDelay(self, value: Optional[Union[bytes, int]]):
        self["RxDelay"] = value

    @property
    def DLSettings(self) -> Optional[Union[bytes, int]]:
        return self.get("DLSettings")

    @DLSettings.setter
    def DLSettings(self, value: Optional[Union[bytes, int]]):
        self["DLSettings"] = value

    @property
    def NetID(self) -> Optional[bytes]:
        return self.get("NetID")

    @NetID.setter
    def NetID(self, value: Optional[bytes]):
        self["NetID"] = value

    @property
    def AppNonce(self) -> Optional[bytes]:
        return self.get("AppNonce")

    @AppNonce.setter
    def AppNonce(self, value: Optional[bytes]):
        self["AppNonce"] = value

    @property
    def DevNonce(self) -> Optional[bytes]:
        return self.get("DevNonce")

    @DevNonce.setter
    def DevNonce(self, value: Optional[bytes]):
        self["DevNonce"] = value

    @property
    def DevEUI(self) -> Optional[bytes]:
        return self.get("DevEUI")

    @DevEUI.setter
    def DevEUI(self, value: Optional[bytes]):
        self["DevEUI"] = value

    @property
    def AppEUI(self) -> Optional[bytes]:
        return self.get("AppEUI")

    @AppEUI.setter
    def AppEUI(self, value: Optional[bytes]):
        self["AppEUI"] = value

    @property
    def FPort(self) -> Optional[int]:
        return self.get("FPort")

    @FPort.setter
    def FPort(self, value: Optional[int]):
        self["FPort"] = value

    @property
    def FOpts(self) -> Optional[Union[bytes, str]]:
        return self.get("FOpts")

    @FOpts.setter
    def FOpts(self, value: Optional[Union[bytes, str]]):
        self["FOpts"] = value

    @property
    def FCnt(self) -> Optional[Union[bytes, int]]:
        return self.get("FCnt")

    @FCnt.setter
    def FCnt(self, value: Optional[Union[bytes, int]]):
        self["FCnt"] = value

    @property
    def MType(self) -> Optional[Union[bytes, int, str]]:
        return self.get("MType")

    @MType.setter
    def MType(self, value: Optional[Union[bytes, int, str]]):
        self["MType"] = value

    @property
    def DevAddr(self) -> Optional[bytes]:
        return self.get("DevAddr")

    @DevAddr.setter
    def DevAddr(self, value: Optional[bytes]):
        self["DevAddr"] = value

    @property
    def Payload(self) -> Optional[Union[bytes, str]]:
        return self.get("Payload")

    @Payload.setter
    def Payload(self, value: Optional[Union[bytes, str]]):
        self["Payload"] = value

    @property
    def FCtrl(self) -> Optional[Dict[str, bool]]:
        return self.get("FCtrl")

    @FCtrl.setter
    def FCtrl(self, value: Optional[Dict[str, bool]]):
        self["FCtrl"] = value

    @property
    def JoinReqType(self) -> Optional[Union[bytes, int]]:
        return self.get("JoinReqType")

    @JoinReqType.setter
    def JoinReqType(self, value: Optional[Union[bytes, int]]):
        self["JoinReqType"] = value

def extract_bytes_from_buffer(buffer: bytes, start: int, end: int) -> bytes:
    return buffer[start:end]

def extract_structured_bytes_from_buffer(
    buffer: bytes,
    packet_structure: Dict[str, Dict[str, Range]]
) -> Dict[str, bytes]:
    structured = {}
    for key, byte_range in packet_structure.items():
        start = byte_range["start"]
        end = byte_range["end"]
        structured[key] = extract_bytes_from_buffer(buffer, start, end)

    return structured

LORAIV = bytes.fromhex("00000000000000000000000000000000")

class KeyType11(Enum):
    FNwkSIntKey = "01"
    AppSKey = "02"
    SNwkSIntKey = "03"
    NwkSEncKey = "04"

class KeyType10(Enum):
    NwkSKey = "01"
    AppSKey = "02"

class KeyTypeJS(Enum):
    JSIntKey = "06"
    JSEncKey = "05"

class KeyTypeWORSession(Enum):
    WorSIntKey = "01"
    WorSEncKey = "02"

@dataclass
class LoraPacket:
    PHYPayload: Optional[bytes] = None
    MHDR: Optional[bytes] = None
    MACPayload: Optional[bytes] = None
    MACPayloadWithMIC: Optional[bytes] = None
    AppEUI: Optional[bytes] = None
    DevEUI: Optional[bytes] = None
    DevNonce: Optional[bytes] = None
    MIC: Optional[bytes] = None
    AppNonce: Optional[bytes] = None
    NetID: Optional[bytes] = None
    DevAddr: Optional[bytes] = None
    DLSettings: Optional[bytes] = None
    RxDelay: Optional[bytes] = None
    CFList: Optional[bytes] = None
    FCtrl: Optional[bytes] = None
    FOpts: Optional[bytes] = None
    FCnt: Optional[bytes] = None
    FHDR: Optional[bytes] = None
    FPort: Optional[bytes] = None
    FRMPayload: Optional[bytes] = None
    JoinReqType: Optional[bytes] = None
    RejoinType: Optional[bytes] = None
    RJCount0: Optional[bytes] = None
    RJCount1: Optional[bytes] = None
    NwkSKey: Optional[bytes] = None # NwkSKey for DataUP/Down; SNwkSIntKey in data 1.1; SNwkSIntKey in Join 1.1
    AppSKey: Optional[bytes] = None # AppSKey for DataUP/Down; FNwkSIntKey in data 1.1; JSIntKey in Join 1.1
    AppKey: Optional[bytes] = None # AppKey for Join 1.0; AppKey in Join 1.1

    @staticmethod
    def from_wire(buffer: bytes) -> 'LoraPacket':
        packet = LoraPacket()
        packet.PHYPayload = buffer

        packet.MHDR = buffer[:1]
        packet.MACPayload = buffer[1:-4]
        packet.MACPayloadWithMIC = buffer[1:]
        packet.MIC = buffer[-4:]

        mtype = packet._get_mtype()

        if mtype == MTypeEnum.JOIN_REQUEST:
            packet._parse_join_request(buffer)
        elif mtype == MTypeEnum.JOIN_ACCEPT:
            packet._parse_join_accept(buffer)
        elif mtype == MTypeEnum.REJOIN_REQUEST:
            packet._parse_rejoin_request(buffer)
        elif packet.is_data_message():
            packet._parse_data_message(buffer)
        else:
            raise ValueError(f"Invalid message type: {mtype}")

        return packet

    def _get_mtype(self) -> int:
        type = MTypeEnum(self.MHDR[0] >> 5) if self.MHDR else None
        return type


    def _update_packet(self):
        if self.MHDR and self.MIC and self._get_mtype() == MTypeEnum.JOIN_REQUEST:
            if self.AppEUI and self.DevEUI and self.DevNonce:
                self.MACPayload = b"".join([
                    reverse_buffer(self.AppEUI),
                    reverse_buffer(self.DevEUI),
                    reverse_buffer(self.DevNonce)
                ])

            self.PHYPayload = b"".join([
                self.MHDR,
                self.MACPayload,
                self.MIC
            ])

            self.MACPayloadWithMIC = self.PHYPayload[1:-4]

        elif self.MHDR and self.MIC and self._get_mtype() == MTypeEnum.JOIN_ACCEPT:
            if self.AppNonce and self.NetID and self.DevAddr and self.DLSettings and self.RxDelay:
                self.MACPayload = b"".join([
                    self.AppNonce,
                    self.NetID,
                    self.DevAddr,
                    self.DLSettings,
                    self.RxDelay
                ])

                self.PHYPayload = b"".join([
                    self.MHDR,
                    self.MACPayload,
                    self.MIC
                ])

                self.MACPayloadWithMIC = self.PHYPayload[1:-4]

        elif self.MHDR and self.MIC and self._get_mtype() == MTypeEnum.REJOIN_REQUEST:
            if self.RejoinType and self.DevEUI and self.RJCount0:
                if self.RejoinType[0] == 0 or self.RejoinType[0] == 2:
                    self.MACPayload = b"".join([
                        self.RejoinType,
                        self.DevEUI,
                        self.RJCount0
                    ])
            elif self.RejoinType[0] == 1:
                self.MACPayload = b"".join([
                    self.RejoinType,
                    self.JoinEUI,
                    self.DevEUI,
                    self.RJCount1
                ])

            self.PHYPayload = b"".join([
                self.MHDR,
                self.MACPayload,
                self.MIC
            ])

            self.MACPayloadWithMIC = self.PHYPayload[1:-4]
        elif self.MHDR and self.MIC and self.is_data_message():
            if self.DevAddr and self.FCtrl and self.FPort and self.FCnt and self.FRMPayload and self.FOpts is not None:
                self.FHDR = b"".join([
                    reverse_buffer(self.DevAddr),
                    self.FCtrl,
                    reverse_buffer(self.FCnt),
                    self.FOpts
                ])

                self.MACPayload = b"".join([
                    self.FHDR,
                    self.FPort,
                    self.FRMPayload
                ])

                self.PHYPayload = b"".join([
                    self.MHDR,
                    self.MACPayload,
                    self.MIC
                ])

                self.MACPayloadWithMIC = self.PHYPayload[1:-4]

    def _parse_data_message(self, buffer: bytes):
        if len(buffer) < 5 + 7:
            raise ValueError("Buffer too small for a data message")

        self.DevAddr = reverse_buffer(buffer[1:5])
        self.FCtrl = reverse_buffer(buffer[5:6])
        self.FCnt = reverse_buffer(buffer[6:8])

        fctrl = self.FCtrl[0]
        fopts_len = fctrl & 0x0f
        self.FOpts = buffer[8:8+fopts_len]
        fhdr_len = 7 + fopts_len
        self.FHDR = buffer[1:1+fhdr_len]

        if fhdr_len == len(buffer):
            self.FPort = b""
            self.FRMPayload = b""
        else:
            self.FPort = buffer[fhdr_len+1:fhdr_len+2]
            self.FRMPayload = buffer[fhdr_len+2:-4]

        """
        self.MACPayload = b"".join([
            self.FHDR,
            self.FPort,
            self.FRMPayload
        ]) """

        if not self.MIC:
            self.MIC = b"\xee" * 4

        self._update_packet()

    def _parse_rejoin_request(self, buffer: bytes):
        if len(buffer) < 5 + 14:
            raise ValueError("Buffer too small for a rejoin request")

        self.RejoinType = buffer[1:2]
        if self.RejoinType[0] == 0 or self.RejoinType[0] == 2:
            self.DevEUI = buffer[2:10]
            self.RJCount0 = buffer[10:12]
        elif self.RejoinType[0] == 1:
            self.JoinEUI = buffer[2:10]
            self.DevEUI = buffer[10:18]
            self.RJCount1 = buffer[18:20]

        self.MACPayload = b"".join([
            self.RejoinType,
            self.DevEUI,
            self.RJCount0
        ])

        if not self.MIC:
            self.MIC = b"\xee" * 4

        self._update_packet()

    def _parse_join_accept(self, buffer: bytes):
        if len(buffer) < 5 + 12:
            raise ValueError("Buffer too small for a join accept")

        self.AppNonce = buffer[1:4]
        self.NetID = buffer[4:7]
        self.DevAddr = buffer[7:11]
        self.DLSettings = buffer[11:12]
        self.RxDelay = buffer[12:13]

        if len(buffer) == 13 + 16 + 4:
            self.CFList = buffer[13:13+16]
        else:
            self.CFList = b""

        self.MACPayload = b"".join([
            self.AppNonce,
            self.NetID,
            self.DevAddr,
            self.DLSettings,
            self.RxDelay,
            self.CFList
        ])

        if not self.MIC:
            self.MIC = b"\xee" * 4

        self._update_packet()

    def _parse_join_request(self, buffer: bytes):
        if len(buffer) < 5 + 18:
            raise ValueError("Buffer too small for a join request")

        self.AppEUI = reverse_buffer(buffer[1:9]) # Aka JoinEUI
        self.DevEUI = reverse_buffer(buffer[9:17])
        self.DevNonce = reverse_buffer(buffer[17:19])

        self.MACPayload = b"".join([
            reverse_buffer(self.AppEUI),
            reverse_buffer(self.DevEUI),
            reverse_buffer(self.DevNonce)
        ])

        if not self.MIC:
            self.MIC = b"\xee" * 4

        self._update_packet()

    def is_data_message(self) -> bool:
        return self._get_mtype() in [MTypeEnum.UNCONFIRMED_DATA_UP, MTypeEnum.UNCONFIRMED_DATA_DOWN, MTypeEnum.CONFIRMED_DATA_UP, MTypeEnum.CONFIRMED_DATA_DOWN]

    def is_join_request_message(self) -> bool:
        return self._get_mtype() == MTypeEnum.JOIN_REQUEST

    def is_join_accept_message(self) -> bool:
        return self._get_mtype() == MTypeEnum.JOIN_ACCEPT

    def is_rejoin_request_message(self) -> bool:
        return self._get_mtype() == MTypeEnum.REJOIN_REQUEST

    # Provide MType as a string
    def get_mtype(self) -> str:
       return MTYPE_DESCRIPTIONS[MTypeEnum(self._get_mtype())] if MTypeEnum(self._get_mtype()) in MTYPE_DESCRIPTIONS else "Proprietary"

    def is_confirmed(self) -> bool:
        return self._get_mtype() in [MTypeEnum.CONFIRMED_DATA_UP, MTypeEnum.CONFIRMED_DATA_DOWN]

    def is_unconfirmed(self) -> bool:
        return self._get_mtype() in [MTypeEnum.UNCONFIRMED_DATA_UP, MTypeEnum.UNCONFIRMED_DATA_DOWN]

      # Provide Direction as a string
    def get_direction(self) -> str:
        mtype = self._get_mtype()
        if mtype.value > 5:
            return "N/A"
        elif mtype.value % 2 == 0:
            return "up"
        else:
            return "down"

    # Provide FCnt as a number
    def get_fcnt(self) -> int:
        return int.from_bytes(self.FCnt, "big")

    # Provide FPort as a number
    def get_fport(self) -> int:
        return int.from_bytes(self.FPort, "big")

    # Provide FCtrl.ACK as a flag
    def get_fctrl_ack(self) -> bool:
        return bool(self.FCtrl[0] & Masks.FCTRL_ACK.value)

    # Provide FCtrl.ADR as a flag
    def get_fctrl_adr(self) -> bool:
        return bool(self.FCtrl[0] & Masks.FCTRL_ADR.value)

    # Provide FPending as a flag
    def get_fctrl_fpending(self) -> bool:
        return bool(self.FCtrl[0] & Masks.FCTRL_FPENDING.value)

    # Provide FCtrl.ADRAckReq as a flag
    def get_fctrl_adrackreq(self) -> bool:
        return bool(self.FCtrl[0] & Masks.FCTRL_ADRACKREQ.value)

    # Provide DLSettings.RX1DRoffset as integer
    def get_dlsettings_rx1droffset(self) -> int:
        return (self.DLSettings[0] & Masks.DLSETTINGS_RXONEDROFFSET_MASK.value) >> Masks.DLSETTINGS_RXONEDROFFSET_POS.value

    # Provide DLSettings.RX2DataRate as integer
    def get_dlsettings_rxtwodatarate(self) -> int:
        return (self.DLSettings[0] & Masks.DLSETTINGS_RXTWODATARATE_MASK.value) >> Masks.DLSETTINGS_RXTWODATARATE_POS.value

    # Provide DLSettings.OptNeg as boolean
    def get_dlsettings_optneg(self) -> bool:
        return (self.DLSettings[0] & Masks.DLSETTINGS_OPTNEG_MASK) >> Masks.DLSETTINGS_OPTNEG_POS.value

    # Provide RxDelay.Del as integer
    def get_rxdelay(self) -> int:
        return (self.RxDelay[0] & Masks.RXDELAY_DEL_MASK.value) >> Masks.RXDELAY_DEL_POS.value

    # Provide CFList.FreqChFour as bytes
    def get_cflist_ch4freq(self) -> int:
        return int.from_bytes(self.CFList[0:3], "big")

    # Provide CFList.FreqChFive as buffer
    def get_cflist_ch5freq(self) -> int:
        return int.from_bytes(self.CFList[3:6], "big")

    # Provide CFList.FreqChSix as buffer
    def get_cflist_ch6freq(self) -> int:
        return int.from_bytes(self.CFList[6:9], "big")

    # Provide CFList.FreqChSeven as buffer
    def get_cflist_ch7freq(self) -> int:
        return int.from_bytes(self.CFList[9:12], "big")

    # getCFListFreqChEight(): Buffer {
    def get_cflist_ch8freq(self) -> int:
        return int.from_bytes(self.CFList[12:15], "big")

    def get_cflist(self) -> Dict:
        return {
            "Ch4Freq": self.get_cflist_ch4freq(),
            "Ch5Freq": self.get_cflist_ch5freq(),
            "Ch6Freq": self.get_cflist_ch6freq(),
            "Ch7Freq": self.get_cflist_ch7freq(),
            "Ch8Freq": self.get_cflist_ch8freq()
        }

    def get_fields(self) -> Dict:
        fields = {}

        if self.is_data_message():
            fields["DevAddr"] = self.DevAddr.hex()
            fields["FCtrl"] = self.FCtrl.hex()
            fields["FCnt"] = self.FCnt.hex()
            fields["FOpts"] = self.FOpts.hex()
            fields["FPort"] = self.FPort.hex()
            fields["FRMPayload"] = self.FRMPayload.hex()
            fields["MType"] = self.MType.hex()
            fields["Payload"] = self.FRMPayload.hex()

        elif self.is_join_request_message():
            fields["AppEUI"] = self.AppEUI.hex()
            fields["DevEUI"] = self.DevEUI.hex()
            fields["DevNonce"] = self.DevNonce.hex()
            fields["MType"] = self.MType.hex()

        elif self.is_join_accept_message():
            fields["AppNonce"] = self.AppNonce.hex()
            fields["NetID"] = self.NetID.hex()
            fields["DevAddr"] = self.DevAddr.hex()
            fields["DLSettings"] = self.DLSettings.hex()
            fields["RxDelay"] = self.RxDelay.hex()
            fields["CFList"] = self.CFList.hex()
            fields["MType"] = self.MType.hex()

        elif self.is_rejoin_request_message():
            fields["RejoinType"] = self.RejoinType.hex()
            fields["DevEUI"] = self.DevEUI.hex()
            fields["RJCount0"] = self.RJCount0.hex()
            fields["MType"] = self.MType.hex()

        return fields

    def to_fields(self) -> Dict:
        return self.get_fields()

    def to_json(self) -> str:
        return json.dumps(self.get_fields())

    def to_bytes(self) -> bytes:
        return self.PHYPayload

    def to_wire(self) -> bytes:
        return self.PHYPayload

    def set_nwk_key(self, key: bytes) -> None:
        self.NwkSKey = key

    def set_app_key(self, key: bytes) -> None:
        self.AppSKey = key

    @staticmethod
    def from_fields(fields: UserFields) -> 'LoraPacket':
        fields = UserFields(**fields)
        if not fields:
            raise ValueError("UserFields are required")

        if not fields.get("MType"):
            raise ValueError("MType is required")

        if DESCRIPTIONS_MTYPE[fields["MType"]] == MTypeEnum.JOIN_REQUEST:
            return LoraPacket.from_join_request_fields(fields)
        elif DESCRIPTIONS_MTYPE[fields["MType"]] == MTypeEnum.JOIN_ACCEPT:
            return LoraPacket.from_join_accept_fields(fields)
        elif DESCRIPTIONS_MTYPE[fields["MType"]] == MTypeEnum.REJOIN_REQUEST:
            return LoraPacket.from_rejoin_request_fields(fields)
        elif DESCRIPTIONS_MTYPE[fields["MType"]] in [MTypeEnum.UNCONFIRMED_DATA_UP, MTypeEnum.UNCONFIRMED_DATA_DOWN, MTypeEnum.CONFIRMED_DATA_UP, MTypeEnum.CONFIRMED_DATA_DOWN]:
            return LoraPacket.from_data_message_fields(fields)
        else:
            raise ValueError(f"Invalid message type: {fields['MType']}")

    @staticmethod
    def from_data_message_fields(fields: UserFields) -> 'LoraPacket':
        packet = LoraPacket()
        if fields.get("AppSKey"):
            packet.AppSKey = fields["AppSKey"]

        if fields.get("NwkSKey"):
            packet.NwkSKey = fields["NwkSKey"]

        if fields.get("DevAddr") and len(fields["DevAddr"]) == 4:
            packet.DevAddr = bytes(fields["DevAddr"])
        else:
            raise ValueError("DevAddr is required in a suitable format")

        if isinstance(fields.get("Payload"), str):
            packet.FRMPayload = bytes(fields["Payload"], "utf-8")
        elif isinstance(fields.get("Payload"), bytes):
            packet.FRMPayload = fields["Payload"]
        else:
            raise ValueError("Payload is required in a suitable format")

        if fields["MType"] is not None:
            if isinstance(fields["MType"], int):
                packet.MHDR = bytes([fields["MType"] << 5])
            elif isinstance(fields["MType"], str):
                mhdr_idx = DESCRIPTIONS_MTYPE.get(fields["MType"])
                if mhdr_idx is not None:
                    packet.MHDR = bytes([mhdr_idx.value << 5])
                else:
                    raise ValueError("MType is unknown")
            else:
                raise ValueError("MType is required in a suitable format")

        if fields["FCnt"] is not None:
            if isinstance(fields["FCnt"], bytes) and len(fields["FCnt"]) == 2:
                packet.FCnt = fields["FCnt"]
            elif isinstance(fields["FCnt"], int):
                packet.FCnt = fields["FCnt"].to_bytes(2, byteorder="big")
            else:
                raise ValueError("FCnt is required in a suitable format")

        if fields["FOpts"] is not None:
            if isinstance(fields["FOpts"], str):
                packet.FOpts = bytes.fromhex(fields["FOpts"])
            elif isinstance(fields["FOpts"], bytes):
                packet.FOpts = fields["FOpts"]
            else:
                raise ValueError("FOpts is required in a suitable format")

            if len(packet.FOpts) > 15:
                raise ValueError("Too many options for piggybacking")
        else:
            packet.FOpts = bytes()

        fctrl = 0
        if fields.get("FCtrl", {}).get("ADR"):
            fctrl |= Masks.FCTRL_ADR.value
        if fields.get("FCtrl", {}).get("ADRACKReq"):
            fctrl |= Masks.FCTRL_ADRACKREQ.value
        if fields.get("FCtrl", {}).get("ACK"):
            fctrl |= Masks.FCTRL_ACK.value
        if fields.get("FCtrl", {}).get("FPending"):
            fctrl |= Masks.FCTRL_FPENDING.value

        fctrl |= len(packet.FOpts) & 0x0F
        packet.FCtrl = bytes([fctrl])

        if fields["FPort"] is not None:
            if 0 <= fields.get("FPort") <= 255:
                packet.FPort = bytes([fields["FPort"]])
            else:
                raise ValueError("FPort is required in a suitable format")

        if packet.MHDR is None:
            packet.MHDR = bytes([MTypeEnum.UNCONFIRMED_DATA_UP << 5])

        if packet.FPort is None:
            if (packet.FRMPayload is not None) and len(packet.FRMPayload) > 0:
                packet.FPort = b'\x01'
            else:
                packet.FPort = b'\x00'

        if packet.FPort is None:
            packet.FPort = b'\x01'

        if packet.FCnt is None:
            packet.FCnt = b'\x00\x00'

        if packet.MIC is None:
            packet.MIC = b'\xee' * 4

        packet._update_packet()
        # do the MIC calculation
        if packet.FPort is not None and packet.FRMPayload is not None and packet.AppSKey is not None and packet.NwkSKey is not None:
            packet.FRMPayload = packet.decrypt() # encrypt and decrypt are the same XOR operation
            packet._update_packet()
            packet.recalculate_mic()
            #packet.MIC = packet.calculate_mic()


        return packet

    @staticmethod
    def from_join_request_fields(fields: UserFields) -> 'LoraPacket':
        if not fields.get("AppEUI"):
            raise ValueError("AppEUI is required")

        if not fields.get("DevEUI"):
            raise ValueError("DevEUI is required")

        if not fields.get("DevNonce"):
            raise ValueError("DevNonce is required")

        packet = LoraPacket()
        packet.AppEUI = fields["AppEUI"]
        packet.DevEUI = fields["DevEUI"]
        packet.DevNonce = fields["DevNonce"]
        packet.MType = fields["MType"]
        packet._update_packet()
        return packet

    @staticmethod
    def from_join_accept_fields(fields: UserFields) -> 'LoraPacket':
        if not fields.get("AppNonce"):
            raise ValueError("AppNonce is required")

        if not fields.get("NetID"):
            raise ValueError("NetID is required")

        if not fields.get("DevAddr"):
            raise ValueError("DevAddr is required")

        if not fields.get("DLSettings"):
            raise ValueError("DLSettings is required")

        if not fields.get("RxDelay"):
            raise ValueError("RxDelay is required")

        packet = LoraPacket()
        packet.AppNonce = fields["AppNonce"]
        packet.NetID = fields["NetID"]
        packet.DevAddr = fields["DevAddr"]
        packet.DLSettings = fields["DLSettings"]
        packet.RxDelay = fields["RxDelay"]
        packet.CFList = fields.get("CFList", b"")
        packet.MType = fields["MType"]
        packet._update_packet()
        return packet

    @staticmethod
    def from_rejoin_request_fields(fields: UserFields) -> 'LoraPacket':
        if not fields.get("RejoinType"):
            raise ValueError("RejoinType is required")

        if not fields.get("DevEUI"):
            raise ValueError("DevEUI is required")

        if not fields.get("RJCount0"):
            raise ValueError("RJCount0 is required")

        packet = LoraPacket()
        packet.RejoinType = fields["RejoinType"]
        packet.DevEUI = fields["DevEUI"]
        packet.RJCount0 = fields["RJCount0"]
        packet.MType = fields["MType"]
        packet._update_packet()
        return packet

    def __str__(self) -> str:
        return f"LoraPacket: {self.to_string()}"

    def to_string(self) -> str:
        msg = ""

        if self.is_join_request_message():
            msg += "Message Type = Join Request\n"
            msg += f"PHYPayload = {self.PHYPayload.hex().upper()}\n\n"

            msg += "( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n"
            msg += f"MHDR            = {self.MHDR.hex().upper()}\n"
            msg += f"MACPayload = {self.MACPayload.hex().upper()}\n"
            msg += f"MIC                = {self.MIC.hex().upper()}" + " MIC (OK)\n" if (self.AppSKey and self.verify_mic()) else " MIC (BAD != " + as_hex_string(self.calculate_mic()) + ")\n" if self.AppSKey else "\n"
            msg += "\n"

            msg += "( MACPayload = AppEUI[8] | DevEUI[8] | DevNonce[2] )\n"
            msg += f"AppEUI     = {self.AppEUI.hex().upper()}\n"
            msg += f"DevEUI     = {self.DevEUI.hex().upper()}\n"
            msg += f"DevNonce = {self.DevNonce.hex().upper()}\n"

        elif self.is_join_accept_message():
            msg += "Message Type = Join Accept\n"
            msg += f"PHYPayload = {self.PHYPayload.hex().upper()}\n\n"

            msg += "( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n"
            msg += f"MHDR            = {self.MHDR.hex().upper()}\n"
            msg += f"MACPayload = {self.MACPayload.hex().upper()}\n"
            msg += f"MIC                = {self.MIC.hex().upper()}" + " MIC (OK)\n" if self.verify_mic() else " MIC (BAD != " + as_hex_string(self.calculate_mic()) + ")\n"
            msg += "\n"

            msg += "( MACPayload = AppNonce[3] | NetID[3] | DevAddr[4] | DLSettings[1] | RxDelay[1] | CFList[0|15] )\n"
            msg += f"AppNonce     = {self.AppNonce.hex().upper()}\n"
            msg += f"NetID            = {self.NetID.hex().upper()}\n"
            msg += f"DevAddr        = {self.DevAddr.hex().upper()}\n"
            msg += f"DLSettings = {self.DLSettings.hex().upper()}\n"
            msg += f"RxDelay        = {self.RxDelay.hex().upper()}\n"
            msg += f"CFList         = {self.CFList.hex().upper()}\n"

            msg += f"DLSettings.RX1DRoffset = {self.get_dlsettings_rx1droffset()}\n"
            msg += f"DLSettings.RX2DataRate = {self.get_dlsettings_rxtwodatarate()}"
            msg += f"DLSettings.Delay             = {self.get_rxdelay()}\n"
            msg += "\n"

            if self.CFList.length == 16:
                msg += "( CFList = FreqCh4[3] | FreqCh5[3] | FreqCh6[3] | FreqCh7[3] | FreqCh8[3] )\n"
                msg += f"CFList.Ch4Freq = {self.get_cflist_ch4freq()}\n"
                msg += f"CFList.Ch5Freq = {self.get_cflist_ch5freq()}\n"
                msg += f"CFList.Ch6Freq = {self.get_cflist_ch6freq()}\n"
                msg += f"CFList.Ch7Freq = {self.get_cflist_ch7freq()}\n"
                msg += f"CFList.Ch8Freq = {self.get_cflist_ch8freq()}\n"
                msg += "\n"

        elif self.is_rejoin_request_message():
            msg += "Message Type = Rejoin Request\n"
            msg += f"PHYPayload = {self.PHYPayload.hex().upper()}\n\n"

            msg += "( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n"
            msg += f"MHDR            = {self.MHDR.hex().upper()}\n"
            msg += f"MACPayload = {self.MACPayload.hex().upper()}\n"
            msg += f"MIC                = {self.MIC.hex().upper()}" + " MIC (OK)\n" if (self.AppSKey and self.verify_mic()) else " MIC (BAD != " + as_hex_string(self.calculate_mic()) + ")\n" if self.AppSKey else "\n"
            msg += "\n"

            if self.RejoinType[0] == 0 or self.RejoinType[0] == 2:
                msg += "( MACPayload = RejoinType[1] | NetID[3] | DevEUI[8] | RJCount0[2] )\n"
                msg += f"RejoinType = {self.RejoinType.hex().upper()}\n"
                msg += f"DevEUI         = {self.DevEUI.hex().upper()}\n"
                msg += f"RJCount0     = {self.RJCount0.hex().upper()}\n"
            elif self.RejoinType[0] == 1:
                msg += "( MACPayload = RejoinType[1] | JoinEUI[8] | DevEUI[8] | RJCount0[2] )\n"
                msg += f"RejoinType = {self.RejoinType.hex().upper()}\n"
                msg += f"JoinEUI        = {self.JoinEUI.hex().upper()}\n"
                msg += f"DevEUI         = {self.DevEUI.hex().upper()}\n"
                msg += f"RJCount0     = {self.RJCount0.hex().upper()}\n"

        elif self.is_data_message():
            msg += "Message Type = Data\n"

            msg += f"PHYPayload = {self.PHYPayload.hex().upper()}\n"
            msg += "\n"

            msg += "( PHYPayload = MHDR[1] | MACPayload[..] | MIC[4] )\n"
            msg += f"MHDR            = {self.MHDR.hex().upper()}\n"
            msg += f"MACPayload = {self.MACPayload.hex().upper()}\n"
            msg += f"MIC                = {self.MIC.hex().upper()}" + " MIC (OK)\n" if (self.NwkSKey and self.verify_mic()) else " MIC (BAD != " + as_hex_string(self.calculate_mic()) + ")\n" if self.NwkSKey else "\n"
            msg += "\n"

            msg += "( MACPayload = FHDR | FPort | FRMPayload )\n"
            msg += f"FHDR             = {self.FHDR.hex().upper()}\n"
            msg += f"FPort            = {self.FPort.hex().upper()}\n"
            msg += f"FRMPayload = {self.FRMPayload.hex().upper()}" + f"\nFRMPayload Plaintext = {self.decrypt().hex().upper()}\n" if self.AppSKey else ""
            msg += "\n"

            msg += "( FHDR = DevAddr[4] | FCtrl[1] | FCnt[2] | FOpts[0..15] )\n"
            msg += f"DevAddr = {self.DevAddr.hex().upper()}\n"
            msg += f"FCtrl     = {self.FCtrl.hex().upper()}\n"
            msg += f"FCnt        = {self.FCnt.hex().upper()}\n"
            msg += f"FOpts     = {self.FOpts.hex().upper()}\n"
            msg += "\n"

            msg += f"Message Type = {self.get_mtype()}\n"
            msg += f"Direction        = {self.get_direction()}\n"
            msg += f"FCnt                 = {self.get_fcnt()}\n"
            msg += f"FCtrl.ACK        = {self.get_fctrl_ack()}\n"
            msg += f"FCtrl.ADR        = {self.get_fctrl_adr()}\n"
            if (self._get_mtype() == MTypeEnum.CONFIRMED_DATA_DOWN) or (self._get_mtype() == MTypeEnum.UNCONFIRMED_DATA_DOWN) :
                msg += f"FCtrl.FPending    = {self.get_fctrl_fpending()}\n"
            else:
                msg += f"FCtrl.ADRACKReq = {self.get_fctrl_adrackreq()}\n"

        return msg


    def calculate_mic(
        self,
        FCntMSBytes: Optional[bytes] = None,
        ConfFCntDownTxDrTxCh: Optional[bytes] = None
    ) -> bytes:
        LWVersion = LoRaWANVersion.V1_0
        if not self.NwkSKey:
            raise ValueError("NwkSKey is required")

        if self.is_join_request_message():
            if not self.AppSKey:
                raise ValueError("AppKey is required")
            if self.AppSKey and len(self.AppSKey) != 16:
                raise ValueError("Expected an AppKey with length 16")
            if not self.MHDR:
                raise ValueError("Expected MHDR to be defined")
            if not self.AppEUI:
                raise ValueError("Expected AppEUI to be defined")
            if not self.DevEUI:
                raise ValueError("Expected DevEUI to be defined")
            if not self.DevNonce:
                raise ValueError("Expected DevNonce to be defined")
            if not self.MACPayload:
                raise ValueError("Expected MACPayload to be defined")

            cmac_input = self.MHDR + self.MACPayload

            cmac = CMAC.new(self.AppSKey, ciphermod=AES)
            cmac.update(cmac_input)
            full_cmac = cmac.digest()
            MIC = full_cmac[:4]

            return MIC

        elif self.is_rejoin_request_message():
            if not self.AppSKey or not self.NwkSKey:
                raise ValueError("AppKey and NwkSKey are required")
            if self.RejoinType[0] == 1 and (not self.AppSKey or len(self.AppSKey) != 16):
                raise ValueError("Expected a JSIntKey with length 16")
            if (self.RejoinType[0] == 0 or self.RejoinType[0] == 2) and (not self.NwkSKey or len(self.NwkSKey) != 16):
                raise ValueError("Expected a SNwkSIntKey with length 16")
            if self.AppSKey and len(self.AppSKey) != 16:
                raise ValueError("Expected an AppKey with length 16")
            if not self.MHDR:
                raise ValueError("Expected MHDR to be defined")
            if not self.RejoinType:
                raise ValueError("Expected RejoinType to be defined")
            if not self.NetID and not self.AppEUI:
                raise ValueError("Expected NetID or JoinEUI to be defined")
            if not self.DevEUI:
                raise ValueError("Expected DevEUI to be defined")
            if not self.RJCount0 and not self.RJCount1:
                raise ValueError("Expected RJCount0 or RJCount1 to be defined")

            cmac_input = self.MHDR + self.MACPayload

            calc_key = self.AppSKey if self.RejoinType[0] == 1 else self.NwkSKey
            cmac = CMAC.new(calc_key, ciphermod=AES)
            cmac.update(cmac_input)
            full_cmac = cmac.digest()
            MIC = full_cmac[:4]

            return MIC

        elif self.is_join_accept_message():
            if not self.AppSKey or not self.NwkSKey:
                raise ValueError("AppKey and NwkSKey are required")
            if self.AppSKey and len(self.AppSKey) != 16:
                raise ValueError("Expected an AppKey with length 16")
            if not self.MHDR:
                raise ValueError("Expected MHDR to be defined")
            if not self.AppNonce:
                raise ValueError("Expected AppNonce to be defined")
            if not self.NetID:
                raise ValueError("Expected NetID to be defined")
            if not self.DevAddr:
                raise ValueError("Expected DevAddr to be defined")
            if not self.DLSettings:
                raise ValueError("Expected DLSettings to be defined")
            if not self.RxDelay:
                raise ValueError("Expected RxDelay to be defined")
            if not self.CFList:
                raise ValueError("Expected CFList to be defined")
            if not self.MACPayload:
                raise ValueError("Expected MACPayload to be defined")
            if self.get_dlsettings_optneg():
                LWVersion = LoRaWANVersion.V1_1

            cmac_input = b""
            cmac_key = self.AppSKey

            if LWVersion == LoRaWANVersion.V1_0:
                cmac_input = self.MHDR + self.MACPayload
            elif LWVersion == LoRaWANVersion.V1_1:
                if not self.JoinReqType:
                    raise ValueError("Expected JoinReqType to be defined")
                if not self.JoinEUI:
                    raise ValueError("Expected JoinEUI to be defined")
                if not self.DevNonce:
                    raise ValueError("Expected DevNonce to be defined")
                if not self.NwkSKey or len(self.NwkSKey) != 16:
                    raise ValueError("Expected a NwkSKey with length 16")
                cmac_key = self.NwkSKey
                cmac_input = self.JoinReqType + reverse_buffer(self.JoinEUI) + \
                    reverse_buffer(self.DevNonce) + self.MHDR + self.MACPayload

            cmac = CMAC.new(cmac_key, ciphermod=AES)
            cmac.update(cmac_input)
            full_cmac = cmac.digest()
            MIC = full_cmac[:4]

            return MIC

        else:
            if self.NwkSKey and len(self.NwkSKey) != 16:
                raise ValueError("Expected a NwkSKey with length 16")
            if self.DevAddr and len(self.DevAddr) != 4:
                raise ValueError("Expected a payload DevAddr with length 4")
            if self.FCnt and len(self.FCnt) != 2:
                raise ValueError("Expected a payload FCnt with length 2")
            if not self.MHDR:
                raise ValueError("Expected MHDR to be defined")
            if not self.DevAddr:
                raise ValueError("Expected DevAddr to be defined")
            if not self.FCnt:
                raise ValueError("Expected FCnt to be defined")
            if not self.MACPayload:
                raise ValueError("Expected MACPayload to be defined")
            if not FCntMSBytes:
                FCntMSBytes = b'\x00\x00'

            if ConfFCntDownTxDrTxCh:
                if not self.AppSKey or len(self.AppSKey) != 16:
                    raise ValueError("Expected a FNwkSIntKey with length 16")
                LWVersion = LoRaWANVersion.V1_1


            is_uplink_and_is_1_1 = self.get_direction() == "up" and LWVersion == LoRaWANVersion.V1_1

            is_downlink_and_is_1_1 = self.get_direction() == "down" and LWVersion == LoRaWANVersion.V1_1


            if self.get_direction() == "up":
                dir_bytes = b'\x00'
            elif self.get_direction() == "down":
                dir_bytes = b'\x01'
                if not ConfFCntDownTxDrTxCh:
                    ConfFCntDownTxDrTxCh = b'\x00\x00\x00\x00'
                elif ConfFCntDownTxDrTxCh and len(ConfFCntDownTxDrTxCh) != 2:
                    raise ValueError("Expected a ConfFCntDown with length 2")
                else:
                    ConfFCntDownTxDrTxCh += b'\x00\x00'
            else:
                raise ValueError("Expecting direction to be either 'up' or 'down'")

            if is_uplink_and_is_1_1:
                if not ConfFCntDownTxDrTxCh or len(ConfFCntDownTxDrTxCh) != 4:
                    raise ValueError("Expected a ConfFCntDownTxDrTxCh with length 4 (ConfFCnt | TxDr | TxCh)")

                if self.get_fctrl_ack() or (is_uplink_and_is_1_1 and self.get_fport() == 0):
                    #ConfFCntDownTxDrTxCh = bytes([ConfFCntDownTxDrTxCh[1], ConfFCntDownTxDrTxCh[0], ConfFCntDownTxDrTxCh[2], ConfFCntDownTxDrTxCh[3]])
                    ConfFCntDownTxDrTxCh = ConfFCntDownTxDrTxCh[1::-1] + ConfFCntDownTxDrTxCh[2:]
                else:
                    ConfFCntDownTxDrTxCh = b'\x00\x00' + ConfFCntDownTxDrTxCh[2:]

            msgLen = len(self.MHDR) + len(self.MACPayload)

            B0 = b'\x49' + \
                (ConfFCntDownTxDrTxCh if is_downlink_and_is_1_1 else bytes(4)) + \
                dir_bytes + \
                reverse_buffer(self.DevAddr) + \
                reverse_buffer(self.FCnt) + \
                FCntMSBytes + \
                b'\x00' + \
                msgLen.to_bytes(1)

            cmac_input = B0 + self.MHDR + self.MACPayload

            key = self.AppSKey if is_downlink_and_is_1_1 else self.NwkSKey
            cmac = CMAC.new(key, ciphermod=AES)
            cmac.update(cmac_input)
            full_cmac = cmac.digest()
            MIC = full_cmac[:4]

            if is_uplink_and_is_1_1:
                B1 = b'\x49' + \
                    ConfFCntDownTxDrTxCh + \
                    dir_bytes + \
                    reverse_buffer(self.DevAddr) + \
                    reverse_buffer(self.FCnt) + \
                    FCntMSBytes + \
                    b'\x00' + \
                   msgLen.to_bytes(1)

                cmac_s_input = B1 + self.MHDR + self.MACPayload
                cmac_s = CMAC.new(self.AppSKey, ciphermod=AES)
                cmac_s.update(cmac_s_input)
                full_cmac_s = cmac_s.digest()
                MICS = full_cmac_s[:4]

                return MICS[:2] + MIC[:2]

            return MIC

    def verify_mic(
        self,
        FCntMSBytes: Optional[bytes] = None,
        ConfFCntDownTxDrTxCh: Optional[bytes] = None
    ) -> bool:
        if self.MIC and len(self.MIC) != 4:
            raise ValueError("Expected a payload MIC with length 4")

        calculated = self.calculate_mic(FCntMSBytes, ConfFCntDownTxDrTxCh)
        if not self.MIC:
            return False
        return self.MIC == calculated

    def recalculate_mic(
        self,
        FCntMSBytes: Optional[bytes] = None,
        ConfFCntDownTxDrTxCh: Optional[bytes] = None
    ) -> None:
        calculated = self.calculate_mic(FCntMSBytes, ConfFCntDownTxDrTxCh)
        self.MIC = calculated
        if not self.MHDR:
            raise ValueError("Missing MHDR")
        if not self.MACPayload:
            raise ValueError("Missing MACPayload")
        if not self.MIC:
            raise ValueError("Missing MIC")
        if not self.MHDR:
            raise ValueError("Missing MHDR")
        self.PHYPayload = self.MHDR + self.MACPayload + self.MIC
        self.MACPayloadWithMIC = self.PHYPayload[len(self.MHDR):len(self.PHYPayload)]

    def decrypt(self, fCntMSB32: bytes = None) -> bytes:
        if not self.NwkSKey:
            raise ValueError("Expected a NwkSKey to be defined")
        if not self.AppSKey:
            raise ValueError("Expected an AppSKey to be defined")
        if not self.PHYPayload or not self.FRMPayload:
            raise ValueError("Payload was not defined")

        if not fCntMSB32:
            fCntMSB32 = bytes(2)

        blocks = (len(self.FRMPayload) + 15) // 16

        sequenceS = bytearray(16 * blocks)
        for block in range(blocks):
            ai = self._metadata_block_ai(block, fCntMSB32)
            sequenceS[block * 16 : (block + 1) * 16] = ai

        key = self.NwkSKey if self.get_fport() == 0 else self.AppSKey
        if not key or len(key) != 16:
            raise ValueError("Expected an appropriate key with length 16")

        cipher = AES.new(key, AES.MODE_ECB)
        cipherstream = cipher.encrypt(bytes(sequenceS))

        plaintextPayload = bytearray(len(self.FRMPayload))
        for i in range(len(self.FRMPayload)):
            plaintextPayload[i] = cipherstream[i] ^ self.FRMPayload[i]

        return bytes(plaintextPayload)

    def decrypt_join(self) -> bytes:
        if not self.AppSKey:
            raise ValueError("Expected an AppKey to be defined")
        if not self.MACPayloadWithMIC:
            raise ValueError("Expected parsed payload to be defined")
        if len(self.AppSKey) != 16:
            raise ValueError("Expected an appropriate key with length 16")

        cipher = AES.new(self.AppSKey, AES.MODE_ECB)
        cipherstream = cipher.decrypt(self.MACPayloadWithMIC)
        return cipherstream

    def decrypt_fopts(self, NwkSEncKey: bytes, fCntMSB32: bytes = None) -> bytes:
        if not fCntMSB32:
            fCntMSB32 = bytes(2)

        if not self.FOpts:
            raise ValueError("Expected FOpts to be defined")
        if not self.DevAddr:
            raise ValueError("Expected DevAddr to be defined")
        if len(NwkSEncKey) != 16:
            raise ValueError("Expected an appropriate key with length 16")
        if not self.FCnt:
            raise ValueError("Expected FCnt to be defined")

        direction = bytes(1)
        a_fcnt_down = False

        if self.get_direction() == "up":
            direction = b'\x00'
        elif self.get_direction() == "down":
            direction = b'1'
            if self.FPort is not None and self.get_fport() > 0:
                a_fcnt_down = True
        else:
            raise ValueError("Decrypt error: expecting direction to be either 'up' or 'down'")

        a_buffer = bytes([1]) + bytes(3) + bytes([2 if a_fcnt_down else 1]) + direction + \
                reverse_buffer(self.DevAddr) + reverse_buffer(self.FCnt) + fCntMSB32 + bytes(2)

        cipher = AES.new(NwkSEncKey, AES.MODE_ECB)
        cipherstream = cipher.encrypt(a_buffer)

        plaintextPayload = bytearray(len(self.FOpts))
        for i in range(len(self.FOpts)):
            plaintextPayload[i] = cipherstream[i] ^ self.FOpts[i]

        return bytes(plaintextPayload)

    def generate_key(
        self,
        key: bytes,
        AppNonce: bytes,
        NetIdOrJoinEui: bytes,
        DevNonce: bytes,
        key_type: KeyType11 | KeyType10 | KeyTypeJS | KeyTypeWORSession,
    ) -> bytes:
        key_nonce_str = key_type.value
        key_nonce_str += reverse_buffer(AppNonce).hex()
        key_nonce_str += reverse_buffer(NetIdOrJoinEui).hex()
        key_nonce_str += reverse_buffer(DevNonce).hex()
        key_nonce_str = key_nonce_str.ljust(64, "0")

        key_nonce = bytes.fromhex(key_nonce_str)
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(key_nonce)

    def generate_session_keys(self, AppKey: bytes, NetId: bytes, AppNonce: bytes, DevNonce: bytes):
        return self.generate_session_keys_10(AppKey, NetId, AppNonce, DevNonce)

    def generate_session_keys_10(self, AppKey: bytes, NetId: bytes, AppNonce: bytes, DevNonce: bytes):
        if len(AppKey) != 16:
            raise ValueError("Expected an AppKey with length 16")
        if len(NetId) != 3:
            raise ValueError("Expected a NetId with length 3")
        if len(AppNonce) != 3:
            raise ValueError("Expected an AppNonce with length 3")
        if len(DevNonce) != 2:
            raise ValueError("Expected a DevNonce with length 2")

        return {
            "AppSKey": self.generate_key(AppKey, AppNonce, NetId, DevNonce, KeyType10.AppSKey),
            "NwkSKey": self.generate_key(AppKey, AppNonce, NetId, DevNonce, KeyType10.NwkSKey),
        }

    def generate_session_keys_11(self, AppKey: bytes, NwkKey: bytes, JoinEUI: bytes, AppNonce: bytes, DevNonce: bytes):
        if len(AppKey) != 16:
            raise ValueError("Expected an AppKey with length 16")
        if len(NwkKey) != 16:
            raise ValueError("Expected a NwkKey with length 16")
        if len(AppNonce) != 3:
            raise ValueError("Expected an AppNonce with length 3")
        if len(DevNonce) != 2:
            raise ValueError("Expected a DevNonce with length 2")

        return {
            "AppSKey": self.generate_key(AppKey, AppNonce, JoinEUI, DevNonce, KeyType11.AppSKey),
            "FNwkSIntKey": self.generate_key(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.FNwkSIntKey),
            "SNwkSIntKey": self.generate_key(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.SNwkSIntKey),
            "NwkSEncKey": self.generate_key(NwkKey, AppNonce, JoinEUI, DevNonce, KeyType11.NwkSEncKey),
        }

    def generate_js_keys(self, NwkKey: bytes, DevEui: bytes):
        if len(DevEui) != 8:
            raise ValueError("Expected a DevEui with length 8")
        if len(NwkKey) != 16:
            raise ValueError("Expected a NwkKey with length 16")

        return {
            "JSIntKey": self.generate_key(NwkKey, DevEui, bytes(0), bytes(0), KeyTypeJS.JSIntKey),
            "JSEncKey": self.generate_key(NwkKey, DevEui, bytes(0), bytes(0), KeyTypeJS.JSEncKey),
        }

    def generate_wor_key(self, NwkSKey: bytes):
        if len(NwkSKey) != 16:
            raise ValueError("Expected a NwkKey/NwkSEncKey with length 16")

        return {
            "RootWorSKey": self.generate_key(NwkSKey, bytes(0), bytes(0), bytes(0), KeyTypeWORSession.WorSIntKey),
        }

    def generate_wor_session_keys(self, RootWorSKey: bytes, DevAddr: bytes):
        if len(DevAddr) != 4:
            raise ValueError("Expected a DevAddr with length 4")
        if len(RootWorSKey) != 16:
            raise ValueError("Expected a RootWorSKey with length 16")

        return {
            "WorSIntKey": self.generate_key(RootWorSKey, DevAddr, bytes(0), bytes(0), KeyTypeWORSession.WorSIntKey),
            "WorSEncKey": self.generate_key(RootWorSKey, DevAddr, bytes(0), bytes(0), KeyTypeWORSession.WorSEncKey),
        }

    def encrypt(self, buffer: bytes, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext = cipher.encrypt(buffer)
        return ciphertext

    def decrypt_join_accept(self) -> bytes:
        payloadBuffer = self.PHYPayload or bytes(0)
        mhdr = payloadBuffer[:1]
        joinAccept = self.encrypt(payloadBuffer[1:], self.AppSKey)
        return mhdr + joinAccept

    def _metadata_block_ai(self, blockNumber: int, fCntMSB32: bytes = None) -> bytes:
        if not fCntMSB32:
            fCntMSB32 = bytes(2)

        if self.get_direction() == "up":
            direction = bytes([0])
        elif self.get_direction() == "down":
            direction = bytes([1])
        else:
            raise ValueError("Decrypt error: expecting direction to be either 'up' or 'down'")

        if not self.DevAddr:
            raise ValueError("Decrypt error: DevAddr not defined")
        if not self.FCnt:
            raise ValueError("Decrypt error: FCnt not defined")

        ai_buffer = bytes.fromhex("0100000000") + direction + reverse_buffer(self.DevAddr) + \
                reverse_buffer(self.FCnt) + fCntMSB32 + bytes([0, blockNumber + 1])

        return ai_buffer
