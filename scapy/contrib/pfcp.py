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
    MultipleTypeField, PacketListField, ShortEnumField
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

IE_Types = {
    0   : "Reserved",
    1   : "Create PDR",
    2   : "PDI",
    3   : "Create FAR",
    4   : "Forwarding Parameters",
    5   : "Duplicating Parameters",
    6   : "Create URR",
    7   : "Create QER",
    8   : "Created PDR",
    9   : "Update PDR",
    10  : "Update FAR",
    11  : "Update Forwarding Parameters",
    12  : "Update BAR (PFCP Session Report Response)",
    13  : "Update URR",
    14  : "Update QER",
    15  : "Remove PDR",
    16  : "Remove FAR",
    17  : "Remove URR",
    18  : "Remove QER",
    19  : "Cause",
    20  : "Source Interface",
    21  : "F-TEID",
    22  : "Network Instance",
    23  : "SDF Filter",
    24  : "Application ID",
    25  : "Gate Status",
    26  : "MBR",
    27  : "GBR",
    28  : "QER Correlation ID",
    29  : "Precedence",
    30  : "Transport Level Marking",
    31  : "Volume Threshold",
    32  : "Time Threshold",
    33  : "Monitoring Time",
    34  : "Subsequent Volume Threshold",
    35  : "Subsequent Time Threshold",
    36  : "Inactivity Detection Time",
    37  : "Reporting Triggers",
    38  : "Redirect Information",
    39  : "Report Type",
    40  : "Offending IE",
    41  : "Forwarding Policy",
    42  : "Destination Interface",
    43  : "UP Function Features",
    44  : "Apply Action",
    45  : "Downlink Data Service Information",
    46  : "Downlink Data Notification Delay",
    47  : "DL Buffering Duration",
    48  : "DL Buffering Suggested Packet Count",
    49  : "PFCPSMReq-Flags",
    50  : "PFCPSRRsp-Flags",
    51  : "Load Control Information",
    52  : "Sequence Number",
    53  : "Metric",
    54  : "Overload Control Information",
    55  : "Timer",
    56  : "Packet Detection Rule ID",
    57  : "F-SEID",
    58  : "Application ID's PFDs",
    59  : "PFD context",
    60  : "Node ID",
    61  : "PFD contents",
    62  : "Measurement Method",
    63  : "Usage Report Trigger",
    64  : "Measurement Period",
    65  : "FQ-CSID",
    66  : "Volume Measurement",
    67  : "Duration Measurement",
    68  : "Application Detection Information",
    69  : "Time of First Packet",
    70  : "Time of Last Packet",
    71  : "Quota Holding Time",
    72  : "Dropped DL Traffic Threshold",
    73  : "Volume Quota",
    74  : "Time Quota",
    75  : "Start Time",
    76  : "End Time",
    77  : "Query URR",
    78  : "Usage Report (in Session Modification Response)",
    79  : "Usage Report (Session Deletion Response)",
    80  : "Usage Report (Session Report Request)",
    81  : "URR ID",
    82  : "Linked URR ID",
    83  : "Downlink Data Report",
    84  : "Outer Header Creation",
    85  : "Create BAR",
    86  : "Update BAR (Session Modification Request)",
    87  : "Remove BAR",
    88  : "BAR ID",
    89  : "CP Function Features",
    90  : "Usage Information",
    91  : "Application Instance ID",
    92  : "Flow Information",
    93  : "UE IP Address",
    94  : "Packet Rate",
    95  : "Outer Header Removal",
    96  : "Recovery Time Stamp",
    97  : "DL Flow Level Marking",
    98  : "Header Enrichment",
    99  : "Error Indication Report",
    100 : "Measurement Information",
    101 : "Node Report Type",
    102 : "User Plane Path Failure Report",
    103 : "Remote GTP-U Peer",
    104 : "UR-SEQN",
    105 : "Update Duplicating Parameters",
    106 : "Activate Predefined Rules",
    107 : "Deactivate Predefined Rules",
    108 : "FAR ID",
    109 : "QER ID",
    110 : "OCI Flags",
    111 : "PFCP Association Release Request",
    112 : "Graceful Release Period",
    113 : "PDN Type",
    114 : "Failed Rule ID",
    115 : "Time Quota Mechanism",
    116 : "User Plane IP Resource Information",
    117 : "User Plane Inactivity Timer",
    118 : "Aggregated URRs",
    119 : "Multiplier",
    120 : "Aggregated URR ID",
    121 : "Subsequent Volume Quota",
    122 : "Subsequent Time Quota",
    123 : "RQI",
    124 : "QFI",
    125 : "Query URR Reference",
    126 : "Additional Usage Reports Information",
    127 : "Create Traffic Endpoint",
    128 : "Created Traffic Endpoint",
    129 : "Update Traffic Endpoint",
    130 : "Remove Traffic Endpoint",
    131 : "Traffic Endpoint ID",
    132 : "Ethernet Packet Filter",
    133 : "MAC address",
    134 : "C-TAG",
    135 : "S-TAG",
    136 : "Ethertype",
    137 : "Proxying",
    138 : "Ethernet Filter ID",
    139 : "Ethernet Filter Properties",
    140 : "Suggested Buffering Packets Count",
    141 : "User ID",
    142 : "Ethernet PDU Session Information",
    143 : "Ethernet Traffic Information",
    144 : "MAC Addresses Detected",
    145 : "MAC Addresses Removed",
    146 : "Ethernet Inactivity Timer",
    147 : "Additional Monitoring Time",
    148 : "Event Quota",
    149 : "Event Threshold",
    150 : "Subsequent Event Quota",
    151 : "Subsequent Event Threshold",
    152 : "Trace Information",
    153 : "Framed-Route",
    154 : "Framed-Routing",
    155 : "Framed-IPv6-Route",
    156 : "Event Time Stamp",
    157 : "Averaging Window",
    158 : "Paging Policy Indicator"
}

class IE_NotImplementedTLV(Packet):
    name = "IE not implemented"
    fields_desc = [ShortEnumField("ietype", 0, IEType),
                   ShortField("length", None),
                   StrLenField("data", "", length_from=lambda x: x.length)]

def IE_Dispatcher(s):
    """Choose the correct Information Element class."""
    # Get the IE type
    ietype = orb(s[0])*16 + orb(s[1])
    cls = ietypecls.get(ietype, IE_NotImplementedTLV)
    return cls[0](s)

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
    name = "PFCP Heartbeat Request"

class PFCPMsgNodeHeartBeatResp(_PFCPMsgNode):
    """ 2 : PFCP Heartbeat Response """
    name = "PFCP Heartbeat Response"

class PFCPMsgNodePfdManagmentReq(_PFCPMsgNode):
    """ 3 : PFCP PFD Management Request """
    name = "PFCP PFD Management Request"

class PFCPMsgNodePfdManagmentResp(_PFCPMsgNode):
    """ 4 : PFCP PFD Management Response """
    name = "PFCP PFD Management Response"


class PFCPMsgNodeAssociationSetupReq(_PFCPMsgNode):
    """ 5 : PFCP Association Setup Request """
    name = "PFCP Association Setup Request"

class PFCPMsgNodeAssociationSetupResp(_PFCPMsgNode):
    """ 6 : PFCP Association Setup Response """
    name = "PFCP Association Setup Response"

class PFCPMsgNodeAssociationUpdateReq(_PFCPMsgNode):
    """ 7 : PFCP Association Update Request """
    name = "PFCP Association Update Request"

class PFCPMsgNodeAssociationUpdateResp(_PFCPMsgNode):
    """ 8 : PFCP Association Update Response """
    name = "PFCP Association Update Response"

class PFCPMsgNodeAssociationReleaseReq(_PFCPMsgNode):
    """ 9 : PFCP Association Release Request """
    name = "PFCP Association Release Request"

class PFCPMsgNodeAssociationReleaseResp(_PFCPMsgNode):
    """ 10 : PFCP Association Release Response """
    name = "PFCP Association Release Response"

class PFCPMsgNodeVersionNotSupportResp(_PFCPMsgNode):
    """ 11 : PFCP Version Not Supported Response """
    name = "PFCP Version Not Supported Response"

class PFCPMsgNodeNodeReportReq(_PFCPMsgNode):
    """ 12 : PFCP Node Report Request """
    name = "PFCP Node Report Request"

class PFCPMsgNodeNodeReportResp(_PFCPMsgNode):
    """ 13 : PFCP Node Report Response """
    name = "PFCP Node Report Response"

class PFCPMsgNodeSessionSetDeleteReq(_PFCPMsgNode):
    """ 14 : PFCP Session Set Deletion Request """
    name = "PFCP Session Set Deletion Request"

class PFCPMsgNodeSessionSetDeleteResp(_PFCPMsgNode):
    """ 15 : PFCP Session Set Deletion Response """
    name = "PFCP Session Set Deletion Response"

class PFCPMsgSessionEstablishReq(_PFCPMsgSession):
    """ 50 : PFCP Session Establishment Request """
    name = "PFCP Session Establishment Request"

class PFCPMsgSessionEstablishResp(_PFCPMsgSession):
    """ 51 : PFCP Session Establishment Response """
    name = "PFCP Session Establishment Response"

class PFCPMsgSessionModificationReq(_PFCPMsgSession):
    """ 52 : PFCP Session Modification Request :"""
    name = "PFCP Session Modification Request"

class PFCPMsgSessionModificationResp(_PFCPMsgSession):
    """ 53 : PFCP Session Modification Response """
    name = "PFCP Session Modification Response"

class PFCPMsgSessionDeletionReq(_PFCPMsgSession):
    """ 54 : PFCP Session Deletion Request """
    name = "PFCP Session Deletion Request"

class PFCPMsgSessionDeletionResp(_PFCPMsgSession):
    """ 55 : PFCP Session Deletion Response """
    name = "PFCP Session Deletion Response"

class PFCPMsgSessionReportReq(_PFCPMsgSession):
    """ 56 : PFCP Session Report Request """
    name = "PFCP Session Report Request"

class PFCPMsgSessionReportReq(_PFCPMsgSession):
    """ 57 : PFCP Session Report Response """
    name = "PFCP Session Report Response"


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
