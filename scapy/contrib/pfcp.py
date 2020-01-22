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
        ConditionalField(ByteField("SpareB", 0), lambda pkt:pkt.S==0)
        PacketListField("IE_List", [], GuessIEType,
            length_from=lambda pkt:pkt.Length - (16 if pkt.S==1 else 8))
    ]

def IE_Dispatcher(s):
    """Choose the correct Information Element class."""

    # Get the IE type
    ietype = orb(s[0])
    cls = ietypecls.get(ietype, Raw)

    # if ietype greater than 128 are TLVs
    if cls is Raw and ietype > 128:
        cls = IE_NotImplementedTLV

    return cls(s)

class PFCPMessaage(Packet):
    """PFPCP Messages"""
    fields_desc = [PacketListField("IEList", None, IE_Dispatcher)]
class _PFCPMsgNode(PFCPMessaage):
    """PFCP Messages For Nodes"""
    pass

class _PFCPMsgSession(PFCPMessaage):
    """PFCP Messages For Session """
    pass

class PFCPMsgNodeHeartBeatReq(_PFCPMsgNode):
    """ 1 : PFCP Heartbeat Request """
    pass

class PFCPMsgNodeHeartBeatResp(_PFCPMsgNode):
    """ 2 : PFCP Heartbeat Response """
    pass

class PFCPMsgNodePfdManagmentReq(_PFCPMsgNode):
    """ 3 : PFCP PFD Management Request """
    pass

class PFCPMsgNodePfdManagmentResp(_PFCPMsgNode):
    """ 4 : PFCP PFD Management Response """
    pass

class PFCPMsgNodeAssociationSetupReq(_PFCPMsgNode):
    """ 5 : PFCP Association Setup Request """
    pass

class PFCPMsgNodeAssociationSetupResp(_PFCPMsgNode):
    """ 6 : PFCP Association Setup Response """
    pass

class PFCPMsgNodeAssociationUpdateReq(_PFCPMsgNode):
    """ 7 : PFCP Association Update Request """
    pass

class PFCPMsgNodeAssociationUpdateResp(_PFCPMsgNode):
    """ 8 : PFCP Association Update Response """
    pass

class PFCPMsgNodeAssociationReleaseReq(_PFCPMsgNode):
    """ 9 : PFCP Association Release Request """
    pass

class PFCPMsgNodeAssociationReleaseResp(_PFCPMsgNode):
    """ 10 : PFCP Association Release Response """
    pass

class PFCPMsgNodeVersionNotSupportResp(_PFCPMsgNode):
    """ 11 : PFCP Version Not Supported Response """
    pass

class PFCPMsgNodeNodeReportReq(_PFCPMsgNode):
    """ 12 : PFCP Node Report Request """
    pass

class PFCPMsgNodeNodeReportResp(_PFCPMsgNode):
    """ 13 : PFCP Node Report Response """
    pass

class PFCPMsgNodeSessionSetDeleteReq(_PFCPMsgNode):
    """ 14 : PFCP Session Set Deletion Request """
    pass

class PFCPMsgNodeSessionSetDeleteResp(_PFCPMsgNode):
    """ 15 : PFCP Session Set Deletion Response """
    pass

class PFCPMsgSessionEstablishReq(_PFCPMsgSession):
    """ 50 : PFCP Session Establishment Request """
    pass

class PFCPMsgSessionEstablishResp(_PFCPMsgSession):
    """ 51 : PFCP Session Establishment Response """
    pass

class PFCPMsgSessionModificationReq(_PFCPMsgSession):
    """ 52 : PFCP Session Modification Request :"""
    pass

class PFCPMsgSessionModificationResp(_PFCPMsgSession):
    """ 53 : PFCP Session Modification Response """
    pass

class PFCPMsgSessionDeletionReq(_PFCPMsgSession):
    """ 54 : PFCP Session Deletion Request """

class PFCPMsgSessionDeletionResp(_PFCPMsgSession):
    """ 55 : PFCP Session Deletion Response """
    pass

class PFCPMsgSessionReportReq(_PFCPMsgSession):
    """ 56	PFCP Session Report Request """
    pass

class PFCPMsgSessionReportReq(_PFCPMsgSession):
    """ 57 : PFCP Session Report Response """
    pass


# Bind GTP-C
bind_bottom_up(UDP, PFCP, dport=8805)
bind_bottom_up(UDP, PFCP, sport=8805)
bind_layers(UDP, PFCP, dport=8805, sport=8805)

bind_layers(PFCP, PFCPMsgNodeHeartBeatReq, S=0, MsgType=1)
bind_layers(PFCP, PFCPMsgNodeHeartBeatResp, S=0, MsgType=1)

bind_layers(PFCP, PFCPMsgNodePfdManagmentReq, S=0, MsgType=3)
bind_layers(PFCP, PFCPMsgNodePfdManagmentResp, S=0, MsgType=4)
bind_layers(PFCP, PFCPMsgNodeAssociationSetupReq, S=0, MsgType=5)
bind_layers(PFCP, PFCPMsgNodeAssociationSetupResp, S=0, MsgType=6)
bind_layers(PFCP, PFCPMsgNodeAssociationUpdateReq, S=0, MsgType=7)
bind_layers(PFCP, PFCPMsgNodeAssociationUpdateResp, S=0, MsgType=8)
bind_layers(PFCP, PFCPMsgNodeAssociationReleaseReq, S=0, MsgType=9)
bind_layers(PFCP, PFCPMsgNodeAssociationReleaseResp, S=0, MsgType=10)
bind_layers(PFCP, PFCPMsgNodeVersionNotSupportResp, S=0, MsgType=11)
bind_layers(PFCP, PFCPMsgNodeNodeReportReq, S=0, MsgType=12)
bind_layers(PFCP, PFCPMsgNodeNodeReportResp, S=0, MsgType=13)
bind_layers(PFCP, PFCPMsgNodeSessionSetDeleteReq, S=0, MsgType=14)
bind_layers(PFCP, PFCPMsgNodeSessionSetDeleteResp, S=0, MsgType=15)
bind_layers(PFCP, PFCPMsgSessionEstablishReq, S=1, MsgType=50)
bind_layers(PFCP, PFCPMsgSessionEstablishResp, S=1, MsgType=51)
bind_layers(PFCP, PFCPMsgSessionModificationReq, S=1, MsgType=52)
bind_layers(PFCP, PFCPMsgSessionModificationResp, S=1, MsgType=53)
bind_layers(PFCP, PFCPMsgSessionDeletionReq, S=1, MsgType=54)
bind_layers(PFCP, PFCPMsgSessionDeletionResp, S=1, MsgType=55)
bind_layers(PFCP, PFCPMsgSessionReportReq, S=1, MsgType=56)
bind_layers(PFCP, PFCPMsgSessionReportReq, S=1, MsgType=57)