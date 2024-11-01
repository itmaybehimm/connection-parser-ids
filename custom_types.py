from enum import Enum


class ConnectionFlag(Enum):
    SF = "SF"  # Connection established and closed normally.
    S0 = "S0"  # Connection attempt observed, but no reply.
    REJ = "REJ"  # Connection attempt rejected by the responder.
    RSTR = "RSTR"  # Connection reset by the responder after initial SYN.
    SH = "SH"  # Syn only (half-open connection).
    RSTO = "RSTO"  # Connection reset by the originator.
    S1 = "S1"  # Connection attempt observed with one packet only.
    S2 = "S2"  # Connection attempt observed with two packets.
    S3 = "S3"  # Connection attempt observed with three packets.
    RSTOS0 = "RSTOS0"  # RST sent in response to no response from destination.
    OTH = "OTH"  # Catch-all for other/unknown connection states.
    # TODO for UDP and ICMP make a NONE flag?


class Protocol(Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class InvalidPacketTypeError(Exception):
    """Custom exception for unsupported packet types."""

    def __init__(self, message: str = "Unsupported packet type"):
        super().__init__(message)


class Service(Enum):
    AOL = "aol"
    AUTH = "auth"
    BGP = "bgp"
    COURIER = "courier"
    CSNET_NS = "csnet_ns"
    CTF = "ctf"
    DAYTIME = "daytime"
    DISCARD = "discard"
    DOMAIN = "domain"
    DOMAIN_U = "domain_u"
    ECHO = "echo"
    ECO_I = "eco_i"
    ECR_I = "ecr_i"
    EFS = "efs"
    EXEC = "exec"
    FINGER = "finger"
    FTP = "ftp"
    FTP_DATA = "ftp_data"
    GOPHER = "gopher"
    HARVEST = "harvest"
    HOSTNAMES = "hostnames"
    HTTP = "http"
    HTTP_2784 = "http_2784"
    HTTP_443 = "http_443"
    HTTP_8001 = "http_8001"
    IMAP4 = "imap4"
    IRC = "IRC"
    ISO_TSAP = "iso_tsap"
    KLOGIN = "klogin"
    KSHELL = "kshell"
    LDAP = "ldap"
    LINK = "link"
    LOGIN = "login"
    MTP = "mtp"
    NAME = "name"
    NETBIOS_DGM = "netbios_dgm"
    NETBIOS_NS = "netbios_ns"
    NETBIOS_SSN = "netbios_ssn"
    NETSTAT = "netstat"
    NNSP = "nnsp"
    NNTP = "nntp"
    NTP_U = "ntp_u"
    OTHER = "other"
    PM_DUMP = "pm_dump"
    POP_2 = "pop_2"
    POP_3 = "pop_3"
    PRINTER = "printer"
    PRIVATE = "private"
    RED_I = "red_i"
    REMOTE_JOB = "remote_job"
    RJE = "rje"
    SHELL = "shell"
    SMTP = "smtp"
    SQL_NET = "sql_net"
    SSH = "ssh"
    SUNRPC = "sunrpc"
    SUPDUP = "supdup"
    SYSTAT = "systat"
    TELNET = "telnet"
    TFTP_U = "tftp_u"
    TIM_I = "tim_i"
    TIME = "time"
    URH_I = "urh_i"
    URP_I = "urp_i"
    UUCP = "uucp"
    UUCP_PATH = "uucp_path"
    VMNET = "vmnet"
    WHOIS = "whois"
    X11 = "X11"
    Z39_50 = "Z39_50"
    UNKNOWN = "unknown"  # Default for unmapped ports or maybe put in Service.OTHER


# Dictionary to map ports to services
PORT_SERVICE_MAP = {
    5190: Service.AOL,
    113: Service.AUTH,
    179: Service.BGP,
    530: Service.COURIER,
    105: Service.CSNET_NS,
    84: Service.CTF,
    13: Service.DAYTIME,
    9: Service.DISCARD,
    53: Service.DOMAIN,
    # 53: Service.DOMAIN_U,
    7: Service.ECHO,
    # 20: Service.ECO_I,
    807: Service.ECR_I,
    520: Service.EFS,
    512: Service.EXEC,
    79: Service.FINGER,
    21: Service.FTP,
    20: Service.FTP_DATA,
    70: Service.GOPHER,
    7080: Service.HARVEST,
    101: Service.HOSTNAMES,
    80: Service.HTTP,
    2784: Service.HTTP_2784,
    443: Service.HTTP_443,
    8001: Service.HTTP_8001,
    143: Service.IMAP4,
    194: Service.IRC,
    102: Service.ISO_TSAP,
    543: Service.KLOGIN,
    544: Service.KSHELL,
    389: Service.LDAP,
    245: Service.LINK,
    513: Service.LOGIN,
    57: Service.MTP,
    42: Service.NAME,
    138: Service.NETBIOS_DGM,
    137: Service.NETBIOS_NS,
    139: Service.NETBIOS_SSN,
    15: Service.NETSTAT,
    433: Service.NNSP,
    119: Service.NNTP,
    123: Service.NTP_U,
    99: Service.OTHER,
    616: Service.PM_DUMP,
    109: Service.POP_2,
    110: Service.POP_3,
    515: Service.PRINTER,
    259: Service.PRIVATE,
    355: Service.RED_I,
    # 72: Service.REMOTE_JOB,
    77: Service.RJE,
    514: Service.SHELL,
    25: Service.SMTP,
    1521: Service.SQL_NET,
    22: Service.SSH,
    111: Service.SUNRPC,
    95: Service.SUPDUP,
    11: Service.SYSTAT,
    23: Service.TELNET,
    69: Service.TFTP_U,
    39: Service.TIM_I,
    37: Service.TIME,
    209: Service.URH_I,
    4045: Service.URP_I,
    540: Service.UUCP,
    117: Service.UUCP_PATH,
    175: Service.VMNET,
    43: Service.WHOIS,
    6000: Service.X11,
    210: Service.Z39_50,
}
