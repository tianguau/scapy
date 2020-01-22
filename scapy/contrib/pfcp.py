# scapy.contrib.description = Packet Forwarding Control Protocol(PFCP)
# scapy.contrib.status = loads

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

"""
PFCP extension for Scapy <http://www.secdev.org/scapy>

This module provides Scapy layers for the Packet Forwarding Control
Protocol as defined in 3GPP TS 29.244.
"""

from scapy.packet import bind_layers, bind_bottom_up, Packet
from scapy.fields import BitField, ByteEnumField, ShortField, \
    ConditionalField, LongField, ThreeBytesField, ByteField, \
    MultipleTypeField, PacketListField
from scapy.layers.inet import UDP

PFCPMsgType = {
    #0 Reserved

	#PFCP Node related messages
    1  : "PFCP Heartbeat Request"
    2  : "PFCP Heartbeat Response"
    3  : "PFCP PFD Management Request"
    4  : "PFCP PFD Management Response"
    5  : "PFCP Association Setup Request"
    6  : "PFCP Association Setup Response"
    7  : "PFCP Association Update Request"
    8  : "PFCP Association Update Response"
    9  : "PFCP Association Release Request"
    10 : "PFCP Association Release Response"
    11 : "PFCP Version Not Supported Response"
    12 : "PFCP Node Report Request"
    13 : "PFCP Node Report Response"
    14 : "PFCP Session Set Deletion Request"
    15 : "PFCP Session Set Deletion Response"
    #16 to 49 For future use

	#PFCP Session related messages
    50 : "PFCP Session Establishment Request"
    51 : "PFCP Session Establishment Response"
    52 : "PFCP Session Modification Request"
    53 : "PFCP Session Modification Response"
    54 : "PFCP Session Deletion Request"
    55 : "PFCP Session Deletion Response"
    56 : "PFCP Session Report Request"
    57 : "PFCP Session Report Response"
    #58 to 99 For future use
	#Other messages
    #100 to 255 For future use
}

class PFCP(Packet) :
    name = "PFCP Header"
    fields_desc = [
        BitField("Version", 1, 3),
        BitField("Spare", 0, 3),
        BitField("MP", 0, 1),
        BitField("S", 0, 1),
        ByteEnumField("MsgType", None, PFCPMsgType),
        ShortField("Length", None),
        ConditionalField(LongField("SEID", None), lambda pkt:pkt.S==1),
        ThreeBytesField("Seq", None),
        ConditionalField(BitField("MsgPriority", 0, 4), lambda pkt:pkt.S==1),
        ConditionalField(BitField("Spare1", 0, 4), lambda pkt:pkt.S==1),
        ConditionalField(ByteField("SpareB", 0), lambda pkt:pkt.S==0),
        PacketListField("IE_List", [], GuessIEType,
            length_from=lambda pkt:pkt.Length - (16 if pkt.S==1 else 8))
    ]

class PFCPMessaage(Packet):
    def __init__(self,)
class _FPCPMsgNode(PFCPMessaage):
    pass

class _FPCPMsgSession(PFCPMessaage):
    pass



# Bind GTP-C
bind_bottom_up(UDP, PFCP, dport=8805)
bind_bottom_up(UDP, PFCP, sport=8805)
bind_layers(UDP, PFCP, dport=8805, sport=8805)

bind_layers(PFCP, )