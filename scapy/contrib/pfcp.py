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

from scapy.compat import orb
from scapy.packet import bind_layers, bind_bottom_up, Packet
from scapy.fields import BitField, BitEnumField, ByteEnumField, ShortField, \
    ConditionalField, LongField, ThreeBytesField, ByteField, IntField, \
    MultipleTypeField, PacketListField, ShortEnumField, \
    StrLenField, FieldLenField, StrField, IPField, IP6Field
from scapy.layers.inet import UDP

PFCPMsgType = {
    #0 Reserved

    #PFCP Node related messages
    1  : "PFCP Heartbeat Request",
    2  : "PFCP Heartbeat Response",
    3  : "PFCP PFD Management Request",
    4  : "PFCP PFD Management Response",
    5  : "PFCP Association Setup Request",
    6  : "PFCP Association Setup Response",
    7  : "PFCP Association Update Request",
    8  : "PFCP Association Update Response",
    9  : "PFCP Association Release Request",
    10 : "PFCP Association Release Response",
    11 : "PFCP Version Not Supported Response",
    12 : "PFCP Node Report Request",
    13 : "PFCP Node Report Response",
    14 : "PFCP Session Set Deletion Request",
    15 : "PFCP Session Set Deletion Response",
    #16 to 49 For future use

    #PFCP Session related messages
    50 : "PFCP Session Establishment Request",
    51 : "PFCP Session Establishment Response",
    52 : "PFCP Session Modification Request",
    53 : "PFCP Session Modification Response",
    54 : "PFCP Session Deletion Request",
    55 : "PFCP Session Deletion Response",
    56 : "PFCP Session Report Request",
    57 : "PFCP Session Report Response",
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
    ]

IE_Names = {
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

IE_CauseEnum = {
    0   : "Reserved",                                   #Shall not be sent and if received the Cause shall be treated as an invalid IE
    1   : "Request accepted (success)",                 #"Request accepted (success)" is returned when the PFCP entity has accepted a request.
    #2-63   Spare.      This value range shall be used by Cause values in an acceptance response message. See NOTE 1.
    64  : "Request rejected (reason not specified)",    #This cause shall be returned to report an unspecified rejection cause
    65  : "Session context not found",                  #This cause shall be returned, if the F-SEID included in a PFCP Session Modification/Deletion Request message is unknown.
    66  : "Mandatory IE missing",                       #This cause shall be returned when the PFCP entity detects that a mandatory IE is missing in a request message
    67  : "Conditional IE missing",                     #This cause shall be returned when the PFCP entity detects that a Conditional IE is missing in a request message.
    68  : "Invalid length",                             #This cause shall be returned when the PFCP entity detects that an IE with an invalid length in a request message
    69  : "Mandatory IE incorrect",                     #This cause shall be returned when the PFCP entity detects that a Mandatory IE is incorrect in a request message, e.g. the Mandatory IE is malformated or it carries an invalid or unexpected value.
    70  : "Invalid Forwarding Policy",                  #This cause shall be used by the UP function in the PFCP Session Establishment Response or PFCP Session Modification Response message if the CP function attempted to provision a FAR with a Forwarding Policy Identifier for which no Forwarding Policy is locally configured in the UP function.
    71  : "Invalid F-TEID allocation option",           #This cause shall be used by the UP function in the PFCP Session Establishment Response or PFCP Session Modification Response message if the CP function attempted to provision a PDR with a F-TEID allocation option which is incompatible with the F-TEID allocation option used for already created PDRs (by the same or a different CP function).
    72  : "No established PFCP Association",            #This cause shall be used by the CP function or the UP function if they receive a PFCP Session related message from a peer with which there is no established PFCP Association.
    73  : "Rule creation/modification Failure",         #This cause shall be used by the UP function if a received Rule failed to be stored and  be applied in the UP function.
    74  : "PFCP entity in congestion",                  #This cause shall be returned when a PFCP entity has detected node level congestion and performs overload control, which does not allow the request to be processed.
    75  : "No resources available",                     #This cause shall be returned to indicate a temporary unavailability of resources to process the received request.
    76  : "Service not supported",                      #This cause shall be returned when a PFCP entity receives a message requesting a feature or service that is not supported. 
    77  : "System failure",                             #This cause shall be returned to indicate a system error condition. 
    #78 to 255	Spare for future use in a response message. See NOTE 2.	This value range shall be used by Cause values in a rejection response message. See NOTE 2.
}

IE_Enums = {}

class IE_NotImplementedTLV:
    pass

def IE_Dispatcher(s):
    """Choose the correct Information Element class."""
    # Get the IE type
    ietype = orb(s[0])*16 + orb(s[1])
    print(ietype)
    cls = IE_Enums.get(ietype, IE_NotImplementedTLV)
    print(cls)
    result = cls
    if cls is not IE_NotImplementedTLV :
        result.name = IE_Names[ietype]
    else :
        result.name = IE_Names[0]
    print(result.name)
    return result(s)

class IE_Base(Packet):
    def extract_padding(self, pkt):
        return "", pkt

class IE_CreatedPDR(IE_Base):
    fields_desc = [ ShortEnumField("type", 8, IE_Names),
                    FieldLenField("len", 1, length_of="causeid"),
                    PacketListField("IEList", None, cls=IE_Dispatcher)
                  ]
class IE_Cause(IE_Base) :
    fields_desc = [ ShortEnumField("type", 19, IE_Names),
                    FieldLenField("len", 1, length_of="causeid"),
                    ByteEnumField("causeid", 0, IE_CauseEnum),
                    ConditionalField(StrLenField("raw","",length_from=lambda pkt:pkt.len-1), lambda pkt:pkt.len-1)
                  ]
"""
class IE_SrcIntf(IE_Base) :
    fields_desc = [ ShortEnumField("type", 20, IE_Names),
                    FieldLenField("len", )]
"""

"""
class IE_PPI(IE_Base) :
    fields_desc = [ ShortEnumField("type", 158, IE_Names),
                    FieldLenField("len", 1, length_of="PpiVal"),
                    ByteField("ppi", 0),
                    ConditionalField(ByteField("octet"))]
"""

def IE_FTEIDLen(pkt, f):
    pass

class IE_FTEID(IE_Base):
    fields_desc = [ ShortEnumField("type", 21, IE_Names),
                    FieldLenField("len", 1, adjust=IE_FTEIDLen),
                    BitField("spare", 0, 5),
                    BitField("chid", 0, 1),
                    BitField("ch", 0, 1),
                    BitField("v6", 0, 1),
                    BitField("v4", 0, 1),
                    ConditionalField(IntField("TEID", 0), lambda pkt:pkt.ch==0),
                    ConditionalField(IPField("ipv4", 0), lambda pkt:pkt.ch==0 and pkt.v4==1),
                    ConditionalField(IPField("ipv6", 0), lambda pkt:pkt.ch==0 and pkt.v6==1),
                    ConditionalField(ByteField("ChooseID", 0), lambda pkt:pkt.chid==1)
                ##  ConditionalField(StrLenField("raw","",length_from=lambda pkt:pkt.len-2), lambda pkt:pkt.len>2)
                  ]

class IE_PDRID(IE_Base):
    fields_desc = [ ShortEnumField("type", 56, IE_Names),
                    FieldLenField("len", 2, length_of="RuleID"),
                    ShortField("RuleID", 0),
                    ConditionalField(StrLenField("raw","",length_from=lambda pkt:pkt.len-2), lambda pkt:pkt.len>2)
                  ]


def IE_FSEIDSpare(pkt):
    len = pkt.len - 9
    if pkt.v4 :
        len = len - 4
    if pkt.v6 :
        len = len - 16
    return len

def IE_FSEIDLen(pkt, f) :
    len = 9
    if pkt.v4 :
        len = len + 4
    if pkt.v6 :
        len = len + 16
    return len

class IE_FSEID(IE_Base) :
    fields_desc = [ ShortEnumField("type", 57, IE_Names),
                    FieldLenField("len", 1, adjust=IE_FSEIDLen),
                    BitField("spare", 0, 6),
                    BitField("v4", 0, 1),
                    BitField("v6", 0, 1),
                    LongField("TEID", None),
                    ConditionalField(IPField("ipv4", 0), lambda pkt:pkt.v4),
                    ConditionalField(IP6Field("ipv6", 0), lambda pkt:pkt.v6),
                    ConditionalField(StrLenField("raw","",length_from=IE_FSEIDSpare), lambda pkt:IE_FSEIDSpare(pkt)>0)
                  ]

IE_NodeType = {
    0: "IPv4 Address",
    1: "IPv6 Address",
    3: "FQDN"
}

def IE_NodeIDSpare(pkt) :
    if pkt.NodeType == 0 :
        return pkt.len - 1 - 4
    elif pkt.NodeType == 1 :
        return pkt.len - 1 - 16
    elif pkt.NodeType == 2 :
        return 0
    else :
        return pkt.len

def IE_NodeIDLen(pkt, f) :
    if pkt.NodeType == 0 :
        return 4
    elif pkt.NodeType == 1 :
        return 16
    elif pkt.NodeType == 2 :
        return len(pkt.fqdn)
    else :
        return 0

class IE_NodeID(IE_Base) :
    fields_desc =  [ ShortEnumField("type", 60, IE_Names),
                     FieldLenField("len", 1, adjust=IE_NodeIDLen),
                     BitField("spare", 0, 4),
                     BitEnumField("NodeType", 0, 4, IE_NodeType),
                     ConditionalField(IPField("ipv4", 0),  lambda pkt: pkt.NodeType == 0),
                     ConditionalField(IP6Field("ipv6", 0),  lambda pkt: pkt.NodeType == 1),
                     ConditionalField(StrLenField("fqdn", "", length_from=lambda pkt:pkt.len-1),  lambda pkt: pkt.NodeType == 2),
                     ConditionalField(StrLenField("raw","",length_from=IE_NodeIDSpare), lambda pkt:IE_NodeIDSpare(pkt)>0)
                  ]
class IE_NotImplementedTLV(IE_Base):
    fields_desc = [StrField("load", "")]

IE_Enums = {
#    0   : (IE_NotImplementedTLV,    "Reserved"),
#    1   : (IE_CreatePDR,            "Create PDR"),
#    2   : (IE_PDI,                  "PDI"),
#    3   : (IE_CreateFAR,            "Create FAR"),
#    4   : (IE_ForwardingParam,      "Forwarding Parameters"),
#    5   : (IE_DuplicatingParam,     "Duplicating Parameters"),
#    6   : (IE_CreateURR,            "Create URR"),
#    7   : (IE_CreateQER,            "Create QER"),
    8   : IE_CreatedPDR,
#    9   : (IE_UpdatePDR,            "Update PDR"),
#    10  : (IE_UpdateFAR,            "Update FAR"),
#    11  : (IE_UpdateForwardingParam,"Update Forwarding Parameters"),
#    12  : (IE_UpdateBar,            "Update BAR (PFCP Session Report Response)"),
#    13  : (IE_,  "Update URR"),
#    14  : (IE_,  "Update QER"),
#    15  : (IE_,  "Remove PDR"),
#    16  : (IE_,  "Remove FAR"),
#    17  : (IE_,  "Remove URR"),
#    18  : (IE_,  "Remove QER"),
    19  : IE_Cause,
#    20  : (IE_,  "Source Interface"),
    21  : IE_FTEID,
#    22  : (IE_,  "Network Instance"),
#    23  : (IE_,  "SDF Filter"),
#    24  : (IE_,  "Application ID"),
#    25  : (IE_,  "Gate Status"),
#    26  : (IE_,  "MBR"),
#    27  : (IE_,  "GBR"),
#    28  : (IE_,  "QER Correlation ID"),
#    29  : (IE_,  "Precedence"),
#    30  : (IE_,  "Transport Level Marking"),
#    31  : (IE_,  "Volume Threshold"),
#    32  : (IE_,  "Time Threshold"),
#    33  : (IE_,  "Monitoring Time"),
#    34  : (IE_,  "Subsequent Volume Threshold"),
#    35  : (IE_,  "Subsequent Time Threshold"),
#    36  : (IE_,  "Inactivity Detection Time"),
#    37  : (IE_,  "Reporting Triggers"),
#    38  : (IE_,  "Redirect Information"),
#    39  : (IE_,  "Report Type"),
#    40  : (IE_,  "Offending IE"),
#    41  : (IE_,  "Forwarding Policy"),
#    42  : (IE_,  "Destination Interface"),
#    43  : (IE_,  "UP Function Features"),
#    44  : (IE_,  "Apply Action"),
#    45  : (IE_,  "Downlink Data Service Information"),
#    46  : (IE_,  "Downlink Data Notification Delay"),
#    47  : (IE_,  "DL Buffering Duration"),
#    48  : (IE_,  "DL Buffering Suggested Packet Count"),
#    49  : (IE_,  "PFCPSMReq-Flags"),
#    50  : (IE_,  "PFCPSRRsp-Flags"),
#    51  : (IE_,  "Load Control Information"),
#    52  : (IE_,  "Sequence Number"),
#    53  : (IE_,  "Metric"),
#    54  : (IE_,  "Overload Control Information"),
#    55  : (IE_,  "Timer"),
    56  : IE_PDRID,
    57  : IE_FSEID,
#    58  : (IE_,  "Application ID's PFDs"),
#    59  : (IE_,  "PFD context"),
    60  : IE_NodeID,
#    61  : (IE_,  "PFD contents"),
#    62  : (IE_,  "Measurement Method"),
#    63  : (IE_,  "Usage Report Trigger"),
#    64  : (IE_,  "Measurement Period"),
#    65  : (IE_,  "FQ-CSID"),
#    66  : (IE_,  "Volume Measurement"),
#    67  : (IE_,  "Duration Measurement"),
#    68  : (IE_,  "Application Detection Information"),
#    69  : (IE_,  "Time of First Packet"),
#    70  : (IE_,  "Time of Last Packet"),
#    71  : (IE_,  "Quota Holding Time"),
#    72  : (IE_,  "Dropped DL Traffic Threshold"),
#    73  : (IE_,  "Volume Quota"),
#    74  : (IE_,  "Time Quota"),
#    75  : (IE_,  "Start Time"),
#    76  : (IE_,  "End Time"),
#    77  : (IE_,  "Query URR"),
#    78  : (IE_,  "Usage Report (in Session Modification Response)"),
#    79  : (IE_,  "Usage Report (Session Deletion Response)"),
#    80  : (IE_,  "Usage Report (Session Report Request)"),
#    81  : (IE_,  "URR ID"),
#    82  : (IE_,  "Linked URR ID"),
#    83  : (IE_,  "Downlink Data Report"),
#    84  : (IE_,  "Outer Header Creation"),
#    85  : (IE_,  "Create BAR"),
#    86  : (IE_,  "Update BAR (Session Modification Request)"),
#    87  : (IE_,  "Remove BAR"),
#    88  : (IE_,  "BAR ID"),
#    89  : (IE_,  "CP Function Features"),
#    90  : (IE_,  "Usage Information"),
#    91  : (IE_,  "Application Instance ID"),
#    92  : (IE_,  "Flow Information"),
#    93  : (IE_,  "UE IP Address"),
#    94  : (IE_,  "Packet Rate"),
#    95  : (IE_,  "Outer Header Removal"),
#    96  : (IE_,  "Recovery Time Stamp"),
#    97  : (IE_,  "DL Flow Level Marking"),
#    98  : (IE_,  "Header Enrichment"),
#    99  : (IE_,  "Error Indication Report"),
#    100 : (IE_,  "Measurement Information"),
#    101 : (IE_,  "Node Report Type"),
#    102 : (IE_,  "User Plane Path Failure Report"),
#    103 : (IE_,  "Remote GTP-U Peer"),
#    104 : (IE_,  "UR-SEQN"),
#    105 : (IE_,  "Update Duplicating Parameters"),
#    106 : (IE_,  "Activate Predefined Rules"),
#    107 : (IE_,  "Deactivate Predefined Rules"),
#    108 : (IE_,  "FAR ID"),
#    109 : (IE_,  "QER ID"),
#    110 : (IE_,  "OCI Flags"),
#    111 : (IE_,  "PFCP Association Release Request"),
#    112 : (IE_,  "Graceful Release Period"),
#    113 : (IE_,  "PDN Type"),
#    114 : (IE_,  "Failed Rule ID"),
#    115 : (IE_,  "Time Quota Mechanism"),
#    116 : (IE_,  "User Plane IP Resource Information"),
#    117 : (IE_,  "User Plane Inactivity Timer"),
#    118 : (IE_,  "Aggregated URRs"),
#    119 : (IE_,  "Multiplier"),
#    120 : (IE_,  "Aggregated URR ID"),
#    121 : (IE_,  "Subsequent Volume Quota"),
#    122 : (IE_,  "Subsequent Time Quota"),
#    123 : (IE_,  "RQI"),
#    124 : (IE_,  "QFI"),
#    125 : (IE_,  "Query URR Reference"),
#    126 : (IE_,  "Additional Usage Reports Information"),
#    127 : (IE_,  "Create Traffic Endpoint"),
#    128 : (IE_,  "Created Traffic Endpoint"),
#    129 : (IE_,  "Update Traffic Endpoint"),
#    130 : (IE_,  "Remove Traffic Endpoint"),
#    131 : (IE_,  "Traffic Endpoint ID"),
#    132 : (IE_,  "Ethernet Packet Filter"),
#    133 : (IE_,  "MAC address"),
#    134 : (IE_,  "C-TAG"),
#    135 : (IE_,  "S-TAG"),
#    136 : (IE_,  "Ethertype"),
#    137 : (IE_,  "Proxying"),
#    138 : (IE_,  "Ethernet Filter ID"),
#    139 : (IE_,  "Ethernet Filter Properties"),
#    140 : (IE_,  "Suggested Buffering Packets Count"),
#    141 : (IE_,  "User ID"),
#    142 : (IE_,  "Ethernet PDU Session Information"),
#    143 : (IE_,  "Ethernet Traffic Information"),
#    144 : (IE_,  "MAC Addresses Detected"),
#    145 : (IE_,  "MAC Addresses Removed"),
#    146 : (IE_,  "Ethernet Inactivity Timer"),
#    147 : (IE_,  "Additional Monitoring Time"),
#    148 : (IE_,  "Event Quota"),
#    149 : (IE_,  "Event Threshold"),
#    150 : (IE_,  "Subsequent Event Quota"),
#    151 : (IE_,  "Subsequent Event Threshold"),
#    152 : (IE_,  "Trace Information"),
#    153 : (IE_,  "Framed-Route"),
#    154 : (IE_,  "Framed-Routing"),
#    155 : (IE_,  "Framed-IPv6-Route"),
#    156 : (IE_,  "Event Time Stamp"),
#    157 : (IE_,  "Averaging Window"),
#    158 : (IE_,  "Paging Policy Indicator")
}



class PFCPMessaage(Packet):
    """PFPCP Messages"""
    fields_desc = [PacketListField("IEList", None, cls=IE_Dispatcher)]
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

class PFCPMsgSessionReportResp(_PFCPMsgSession):
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
bind_layers(PFCP, PFCPMsgSessionReportResp, S=1, MsgType=57)
