from scapy.all import *

class PTP(Packet):
    name = "PTP"
    fields_desc = [
        BitField("transportSpecific", 0, 4),
        BitField("messageType", 0, 4),
        BitField("minorVersion", 0, 4),
        BitField("majorVersion", 2, 4),
        ShortField("messageLength", 44),
        ByteField("domainNumber", 0),
        ByteField("reserved1", 0),
        ShortField("flags", 0),
        LongField("correctionField", 0),
        IntField("reserved2", 0),
        StrFixedLenField("sourcePortIdentity", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", length=10),
        ShortField("sequenceId", 0),
        ByteField("controlField", 0),
        ByteField("logMessageInterval", 0),
        BitField("originTSSeconds", 0, 48),
        BitField("originTSFracNano", 0, 32),
    ]

bind_layers(Ether, PTP, type=0x88f7)
