import struct
import socket
import asyncio
import random
import time
import ipaddress
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class ScanType(Enum):
    """Reliable, practical scanning methods for real-world use."""
    TCP_CONNECT = "tcp_connect"      # Full connection (reliable, no special privileges needed)
    SYN = "syn_stealth"              # Half-open (faster, stealthier, requires raw sockets)
    UDP = "udp"                      # UDP scan (for UDP services like DNS, SNMP)
    # Removed: FIN, XMAS, NULL, ACK, WINDOW, MAIMON - unreliable in many environments
    # Removed: SCTP variants - rarely used in practice


class PortState(Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNFILTERED = "unfiltered"


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"
    ICMP = "icmp"


@dataclass
class PortResult:
    port: int
    protocol: Protocol
    state: PortState
    service: str = ""
    version: str = ""
    product: str = ""
    extrainfo: str = ""
    hostname: str = ""
    ostype: str = ""
    devicetype: str = ""
    cpe: list = field(default_factory=list)
    tunnel: str = ""
    method: str = ""
    conf: int = 10
    banner: str = ""
    latency: float = 0.0
    rtt: float = 0.0
    reason: str = ""
    reason_ttl: int = 0
    scripts: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    cves: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "info"
    traceroute: list = field(default_factory=list)
    firewall: dict = field(default_factory=dict)
    ssl: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    smb: dict = field(default_factory=dict)
    extra: dict = field(default_factory=dict)


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    is_up: bool = True
    status: str = "up"
    status_reason: str = ""
    ports: list = field(default_factory=list)
    os_matches: list = field(default_factory=list)
    os_fingerprint: str = ""
    mac: str = ""
    vendor: str = ""
    distance: int = 0
    uptime: int = 0
    lastboot: str = ""
    latency: float = 0.0
    traceroute: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    vulns: list = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "info"
    notes: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)


@dataclass
class ScanStats:
    start_time: float = 0.0
    end_time: float = 0.0
    elapsed: float = 0.0
    hosts_up: int = 0
    hosts_down: int = 0
    total_hosts: int = 0
    open_ports: int = 0
    filtered_ports: int = 0
    closed_ports: int = 0
    total_ports: int = 0
    scan_type: str = ""
    timing: int = 3
    reason: str = ""


COMMON_SERVICES = {
    20: 'ftp-data', 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
    37: 'time', 42: 'nameserver', 43: 'whois', 49: 'tacacs',
    53: 'domain', 67: 'bootps', 68: 'bootpc', 69: 'tftp',
    70: 'gopher', 79: 'finger', 80: 'http', 81: 'http',
    82: 'http', 83: 'http', 84: 'http', 88: 'kerberos',
    89: 'matip-type-a', 90: 'matip-type-b', 99: 'metagram-relay',
    100: 'newacct', 106: 'pop3pw', 109: 'pop2', 110: 'pop3',
    111: 'rpcbind', 113: 'ident', 119: 'nntp', 123: 'ntp',
    135: 'msrpc', 136: 'profile', 137: 'netbios-ns', 138: 'netbios-dgm',
    139: 'netbios-ssn', 143: 'imap', 144: 'news', 161: 'snmp',
    162: 'snmptrap', 163: 'cmip-man', 164: 'cmip-agent', 174: 'mailq',
    177: 'xdmcp', 179: 'bgp', 199: 'smux', 210: 'z39.50',
    212: 'atex', 213: 'ipx', 220: 'imap3', 259: 'esro-gen',
    264: 'bgmp', 280: 'http-mgmt', 301: 'unknown', 306: 'unknown',
    311: 'asip-webadmin', 340: 'unknown', 366: 'odmr',
    389: 'ldap', 406: 'imsp', 407: 'timbuktu', 416: 'silverplatter',
    425: 'icad-el', 427: 'svrloc', 443: 'https', 444: 'snpp',
    445: 'microsoft-ds', 458: 'appleqtc', 464: 'kpasswd',
    465: 'smtps', 497: 'dantz', 500: 'isakmp', 512: 'exec',
    513: 'login', 514: 'syslog', 515: 'printer', 524: 'ncp',
    540: 'uucp', 543: 'klogin', 544: 'kshell', 545: 'appleqtcsrvr',
    548: 'afp', 554: 'rtsp', 555: 'dsf', 563: 'nntps',
    587: 'submission', 593: 'http-rpc-epmap', 631: 'ipp',
    636: 'ldaps', 646: 'ldp', 648: 'rsvp', 666: 'doom',
    667: 'disclose', 668: 'mecomm', 683: 'corba-iiop', 687: 'asipregistry',
    691: 'msexch-routing', 700: 'epp', 705: 'agentx', 711: 'cisco-tdp',
    749: 'kerberos-adm', 765: 'webster', 777: 'multiling-http',
    800: 'mdbs_daemon', 801: 'device', 808: 'ccproxy-http',
    843: 'unknown', 873: 'rsync', 880: 'unknown', 888: 'accessbuilder',
    898: 'sun-manageconsole', 900: 'omginitialrefs', 901: 'smpnameres',
    902: 'vmware-auth', 903: 'iss-realsecure', 911: 'xact-backup',
    912: 'apex-mesh', 981: 'unknown', 987: 'unknown', 990: 'ftps',
    992: 'telnets', 993: 'imaps', 995: 'pop3s', 999: 'distinct32',
    1000: 'cadlock', 1001: 'unknown', 1002: 'windows-icfw',
    1007: 'unknown', 1009: 'unknown', 1010: 'surf', 1011: 'unknown',
    1021: 'exp1', 1022: 'exp2', 1023: 'netvenuechat', 1024: 'kdm',
    1025: 'NFS-or-IIS', 1026: 'LSA-or-nterm', 1027: 'IIS',
    1028: 'unknown', 1029: 'ms-lsa', 1033: 'local-netinfo',
    1034: 'active', 1035: 'multidropper', 1036: 'nsstp',
    1037: 'ams', 1038: 'mtqp', 1039: 'sbl', 1040: 'netarx',
    1041: 'danf-ak2', 1042: 'afrog', 1043: 'boinc', 1044: 'dcutility',
    1045: 'fpitp', 1046: 'wfremotertm', 1047: 'neod1', 1048: 'neod2',
    1049: 'td-postman', 1050: 'cma', 1051: 'optima-vnet', 1052: 'ddt',
    1053: 'remote-as', 1054: 'brvread', 1055: 'ansyslmd', 1056: 'vfo',
    1057: 'startron', 1058: 'nim', 1059: 'nimreg', 1060: 'polestar',
    1061: 'kiosk', 1062: 'veracity', 1063: 'kyoceranetdev', 1064: 'jstel',
    1065: 'syscomlan', 1066: 'fpo-fns', 1067: 'instl-boots', 1068: 'instl-bootc',
    1069: 'cognex-insight', 1070: 'gmrupdateserv', 1071: 'bsquare-voip',
    1072: 'cardax', 1073: 'bridgecontrol', 1074: 'warmspotMgmt',
    1075: 'rdrmshc', 1076: 'dab-sti-c', 1077: 'imgames', 1078: 'avocent-proxy',
    1079: 'asprovat', 1080: 'socks', 1081: 'pvuniwien', 1082: 'amt-esd-prot',
    1083: 'ansoft-lm-1', 1084: 'ansoft-lm-2', 1085: 'webobjects',
    1086: 'cplscrambler-lg', 1087: 'cplscrambler-in', 1088: 'cplscrambler-al',
    1089: 'ff-annunc', 1090: 'ff-fms', 1091: 'ff-sm', 1092: 'obrpd',
    1093: 'proofd', 1094: 'rootd', 1095: 'nicelink', 1096: 'cnrprotocol',
    1097: 'sunclustermgr', 1098: 'rmiactivation', 1099: 'rmiregistry',
    1100: 'mctp', 1104: 'xrl', 1105: 'ftranhc', 1106: 'isoipsigport-1',
    1107: 'isoipsigport-2', 1108: 'ratio-adp', 1110: 'webadmstart',
    1111: 'lmsocialserver', 1112: 'icp', 1113: 'ltp-deepspace',
    1114: 'mini-sql', 1117: 'ardus-mtrns', 1119: 'bnetgame', 1121: 'rmpp',
    1122: 'availant-mgr', 1123: 'murray', 1124: 'hpvmmcontrol',
    1126: 'hpvmmdata', 1130: 'casp', 1131: 'caspssl', 1132: 'kvm-via-ip',
    1137: 'trim', 1141: 'mxomss', 1145: 'x9-icue', 1147: 'capioverlan',
    1148: 'elfiq-repl', 1149: 'bvtsonar', 1151: 'unizensus', 1152: 'winpoplanmess',
    1154: 'resacommunity', 1161: 'health-polling', 1162: 'health-trap',
    1163: 'sddp', 1164: 'qsm-proxy', 1165: 'qsm-gui', 1166: 'qsm-remote',
    1169: 'tripwire', 1174: 'fnet-remote-ui', 1175: 'dossier',
    1183: 'llsurfup-http', 1185: 'catchpole', 1186: 'mysql-cluster',
    1187: 'alias', 1192: 'caids-sensor', 1198: 'cajo-discovery',
    1199: 'dmidi', 1201: 'sands-lm', 1213: 'mpc-lifenet', 1216: 'etebac5',
    1217: 'hpss-ndapi', 1218: 'aeroflight-ads', 1219: 'aeroflight-ret',
    1233: 'univ-appserver', 1234: 'search-agent', 1236: 'bvcontrol',
    1244: 'isbconference2', 1247: 'visionpyramid', 1248: 'hermes',
    1270: 'opsmgr', 1271: 'excw', 1272: 'cspmlockmgr', 1277: 'miva-mqs',
    1296: 'dproxy', 1300: 'h323hostcallsc', 1301: 'ci3-software-1',
    1309: 'jtag-server', 1310: 'husky', 1311: 'rxmon', 1319: 'panja-icp',
    1321: 'pip', 1322: 'novation', 1328: 'ewall', 1334: 'writesrv',
    1352: 'lotusnotes', 1400: 'cadkey-tablet', 1433: 'ms-sql-s',
    1434: 'ms-sql-m', 1443: 'ies-lm', 1455: 'esl-lm', 1461: 'ibm_wrless_lan',
    1494: 'ica', 1500: 'vlsi-lm', 1501: 'sais', 1503: 'ms-sna-server',
    1521: 'oracle', 1524: 'ingreslock', 1533: 'virtual-places',
    1556: 'veritas_pbx', 1580: 'tn-tl-r1', 1583: 'simbaexpress',
    1594: 'sixtrak', 1600: 'issd', 1641: 'invision', 1658: 'sixnetudr',
    1666: 'netview-aix-6', 1687: 'nsjtp-ctrl', 1688: 'nsjtp-data',
    1700: 'mps-raft', 1717: 'fj-hdnet', 1718: 'h323gatedisc',
    1719: 'h323gatestat', 1720: 'h323q931', 1721: 'caicci',
    1723: 'pptp', 1755: 'ms-streaming', 1761: 'cft-0', 1782: 'hp-hcip',
    1783: 'finle-lm', 1801: 'msmq', 1805: 'enl', 1839: 'netopia-vo1',
    1840: 'netopia-vo2', 1862: 'mysql-cm-agent', 1863: 'msnp',
    1900: 'upnp', 1914: 'elm-momentum', 1935: 'rtmp', 1947: 'sentinellm',
    1971: 'netop-school', 1972: 'intersys-cache', 1974: 'drp',
    1984: 'bb', 1998: 'x25-svc-port', 1999: 'tcp-id-port',
    2000: 'cisco-sccp', 2001: 'dc', 2002: 'globe', 2003: 'brutus',
    2004: 'mailbox', 2005: 'berknet', 2006: 'invokator', 2007: 'dectalk',
    2008: 'conf', 2009: 'news', 2010: 'search', 2013: 'raid-am',
    2020: 'xinupageserver', 2021: 'servexec', 2022: 'down', 2030: 'device2',
    2033: 'glogger', 2034: 'scoremgr', 2035: 'imsldoc', 2038: 'objectmanager',
    2040: 'lam', 2041: 'interbase', 2042: 'isis', 2043: 'isis-bcast',
    2045: 'cdfunc', 2046: 'sdfunc', 2047: 'dls', 2048: 'dls-monitor',
    2049: 'nfs', 2065: 'dlsrpn', 2099: 'h2250-annex-g', 2100: 'amiganetfs',
    2103: 'zephyr-clt', 2105: 'eklogin', 2106: 'ekshell', 2107: 'talarian-mqs',
    2111: 'kx', 2119: 'gsigatekeeper', 2121: 'ccproxy-ftp', 2126: 'pktcable-cops',
    2135: 'gris', 2144: 'lv-ffx', 2160: 'apc-2160', 2161: 'apc-2161',
    2170: 'eyetv', 2179: 'vmrdp', 2190: 'tivoconnect', 2191: 'tvbus',
    2196: 'unknown', 2200: 'ici', 2222: 'rockwell-csp2', 2251: 'dif-port',
    2260: 'apc-2260', 2288: 'netml', 2301: 'compaq-https', 2323: '3d-nfsd',
    2381: 'compaq-https', 2382: 'ms-olap3', 2383: 'ms-olap4',
    2393: 'ms-olap1', 2394: 'ms-olap2', 2399: 'fmpro-fdal',
    2401: 'cvspserver', 2492: 'groove', 2500: 'rtsserv', 2522: 'windb',
    2525: 'ms-v-worlds', 2557: 'nicetec-mgmt', 2601: 'zebra',
    2604: 'ospfd', 2605: 'bgpd', 2607: 'connection', 2608: 'wag-service',
    2638: 'sybase', 2809: 'corbaloc', 2811: 'gsi-ftp', 2869: 'icpv2',
    2910: 'tqdata', 2920: 'smpnameres', 2967: 'symantec-av',
    2968: 'enpp', 2969: 'essp', 2998: 'issd', 3000: 'ppp',
    3001: 'nessus', 3003: 'cgms', 3005: 'geniuslm', 3007: 'iiops',
    3011: 'trusted-web', 3013: 'giltsk', 3017: 'event_listener',
    3031: 'eppc', 3052: 'powerchute', 3128: 'squid-http',
    3268: 'msft-gc', 3269: 'msft-gc-ssl', 3283: 'netassistant',
    3306: 'mysql', 3333: 'dec-notes', 3372: 'tip2', 3389: 'ms-wbt-server',
    3404: 'nokia-ann-ch1', 3476: 'ecomm', 3493: 'nut', 3517: '802-11-iapp',
    3527: 'microsoft-ds', 3546: 'unknown', 3551: 'apc-3551',
    3580: 'nati-svrloc', 3659: 'apple-sasl', 3689: 'daap',
    3690: 'svn', 3703: 'adobeserver-3', 3766: 'rtps-discovery',
    3784: 'bfd-ctrl', 3800: 'sibg', 3809: 'remoteanything',
    3814: 'netmpi', 3826: 'warppipe', 3828: 'soap-http',
    3851: 'spectardata', 3869: 'ovsam-mgmt', 3871: 'avocent-adsap',
    3872: 'oem-agent', 3878: 'fagordnc', 3914: 'listcrt-port-2',
    3918: 'bmc-grx', 3986: 'mapper-ws-ethd', 3995: 'iss-mgmt-ssl',
    4000: 'icq', 4001: 'newoak', 4002: 'pxc-spvr-ft', 4045: 'nfs-lockd',
    4111: 'xgrid', 4125: 'netscript', 4129: 'netscript', 4224: 'xtgui',
    4242: 'vrml-multi-use', 4279: 'eq3-update', 4321: 'rwhois',
    4343: 'unicall', 4443: 'pharos', 4444: 'krb524', 4445: 'upnotifyp',
    4446: 'n1-fwp', 4449: 'privatewire', 4450: 'camp', 4500: 'nat-t-ike',
    4550: 'dsf', 4567: 'tram', 4662: 'edonkey', 4848: 'sun-appserver-admin',
    4899: 'radmin', 4900: 'hfcs', 4915: 'fastdata', 4998: 'wsdl',
    5000: 'upnp', 5001: 'commplex-link', 5002: 'rfe', 5003: 'fmpro-internal',
    5004: 'avt-profile-1', 5009: 'airport-admin', 5030: 'surfcontrolcpa',
    5033: 'jtnetd-server', 5050: 'mmcc', 5051: 'ida-agent', 5054: 'unot',
    5060: 'sip', 5061: 'sip-tls', 5080: 'onscreen', 5087: 'biimenu',
    5100: 'admdog', 5101: 'admdog', 5102: 'admdog', 5120: 'barracuda-bbs',
    5151: 'esri-sde', 5190: 'aol', 5200: 'targus-getdata', 5214: 'noteza',
    5221: '3exmp', 5222: 'xmpp-client', 5225: 'hp-server', 5226: 'hp-status',
    5269: 'xmpp-server', 5280: 'xmpp-bosh', 5298: 'xmpp-linklocal',
    5300: 'hacl-cfg', 5357: 'wsdapi', 5405: 'netsupport', 5414: 'statusd',
    5432: 'postgresql', 5440: 'pyrrho', 5500: 'fcp-addr-srvr2',
    5510: 'ace-client', 5544: 'sgi-eventmond', 5550: 'cbus',
    5555: 'personal-agent', 5560: 'isqlplus', 5566: 'westec-connect',
    5591: 'tidecp', 5601: 'kdm', 5631: 'pcanywheredata', 5632: 'pcanywherestat',
    5633: 'beorl', 5666: 'nrpe', 5678: 'rrac', 5679: 'dccm',
    5718: 'dpm-agent', 5777: 'dali-port', 5800: 'vnc-http', 5801: 'vnc-http-1',
    5802: 'vnc-http-2', 5825: 'unknown', 5850: 'unknown', 5900: 'vnc',
    5901: 'vnc-1', 5902: 'vnc-2', 5903: 'vnc-3', 5904: 'vnc-4',
    5905: 'vnc-5', 5906: 'vnc-6', 5907: 'vnc-7', 5908: 'vnc-8',
    5909: 'vnc-9', 5910: 'vnc-10', 5911: 'vnc-11', 5912: 'vnc-12',
    5913: 'vnc-13', 5914: 'vnc-14', 5915: 'vnc-15', 5916: 'vnc-16',
    5917: 'vnc-17', 5918: 'vnc-18', 5919: 'vnc-19', 5920: 'vnc-20',
    5984: 'couchdb', 5985: 'wsman', 5986: 'wsmans', 6000: 'X11',
    6001: 'X11:1', 6002: 'X11:2', 6003: 'X11:3', 6004: 'X11:4',
    6005: 'X11:5', 6006: 'X11:6', 6007: 'X11:7', 6009: 'X11:9',
    6025: 'x11-ssh-offset', 6059: 'x11-ssh-offset', 6100: 'syncserver',
    6101: 'backupexec', 6106: 'unknown', 6112: 'dtspcd', 6346: 'gnutella-svc',
    6379: 'redis', 6543: 'lds-distrib', 6547: 'apc-6547', 6548: 'apc-6548',
    6549: 'apc-6549', 6566: 'sane-port', 6580: 'parsec-master',
    6646: 'unknown', 6666: 'irc', 6667: 'irc', 6668: 'irc', 6669: 'irc',
    6699: 'napster', 6789: 'ibm-db2-admin', 6881: 'bittorrent-tracker',
    6901: 'jetstream', 6969: 'acmsoda', 7000: 'afs3-fileserver',
    7001: 'afs3-callback', 7002: 'afs3-prserver', 7004: 'afs3-vlserver',
    7007: 'afs3-bos', 7019: 'doceri-ctl', 7025: 'vmsvc', 7070: 'realserver',
    7100: 'font-service', 7200: 'fodms', 7201: 'dlip', 7402: 'ptk-alink',
    7443: 'oracleas-https', 7496: 'cloudsignaling', 7547: 'cwmp',
    7625: 'imqstomp', 7627: 'imqstomps', 7634: 'hddtemp', 7777: 'cbt',
    7778: 'interwise', 7937: 'nsrexecd', 7938: 'lgtomapper',
    7999: 'irdmi2', 8000: 'http-alt', 8001: 'vcom-tunnel',
    8002: 'teradataordbms', 8007: 'ajp12', 8008: 'http', 8009: 'ajp13',
    8010: 'xmpp', 8011: 'http', 8021: 'ftp-proxy', 8022: 'oa-system',
    8031: 'pro-ed', 8042: 'fs-agent', 8080: 'http-proxy', 8081: 'blackice-icecap',
    8082: 'blackice-alerts', 8083: 'us-cli', 8084: 'us-srv',
    8085: 'unknown', 8086: 'd-s-n', 8087: 'simplifymedia', 8088: 'radan-http',
    8089: 'unknown', 8090: 'opsmessaging', 8093: 'unknown',
    8180: 'unknown', 8181: 'intermapper', 8192: 'sophos',
    8193: 'sophos', 8194: 'sophos', 8200: 'trivnet1', 8222: 'unknown',
    8291: 'winbox', 8300: 'tmi', 8333: 'bitcoin', 8383: 'm2mservices',
    8400: 'cvd', 8402: 'abarsd', 8443: 'https-alt', 8500: 'fmtp',
    8600: 'asterix', 8649: 'ganglia', 8651: 'unknown', 8701: 'unknown',
    8763: 'mc-appserver', 8800: 'sunwebadmin', 8873: 'dxspider',
    8888: 'sun-answerbook', 8899: 'ospf-lite', 8999: 'bctp',
    9000: 'cslistener', 9001: 'etlservicemgr', 9002: 'dynamid',
    9009: 'pichat', 9010: 'sdr', 9040: 'mandelspawn', 9050: 'tor-socks',
    9080: 'glrpc', 9081: 'unknown', 9090: 'zeus-admin', 9091: 'xmltec-xmlmail',
    9099: 'unknown', 9100: 'jetdirect', 9101: 'jetdirect', 9102: 'jetdirect',
    9103: 'jetdirect', 9110: 'unknown', 9111: 'unknown', 9200: 'wap-wsp',
    9207: 'wap-vcard', 9220: 'unknown', 9290: 'unknown', 9415: 'unknown',
    9418: 'git', 9485: 'unknown', 9500: 'ismserver', 9502: 'unknown',
    9503: 'unknown', 9535: 'man', 9575: 'unknown', 9593: 'cvsup',
    9594: 'cvsup', 9595: 'cvsup', 9618: 'unknown', 9666: 'zoomcp',
    9876: 'sd', 9877: 'unknown', 9878: 'unknown', 9898: 'monkeycom',
    9900: 'iua', 9929: 'nping-echo', 9943: 'unknown', 9944: 'unknown',
    9968: 'unknown', 9998: 'distinct', 9999: 'distinct', 10000: 'snet-sensor-mgmt',
    10001: 'scp-config', 10002: 'documentum', 10003: 'documentum_s',
    10004: 'emcrmirccd', 10009: 'swdtp-sv', 10010: 'rxapi',
    10012: 'unknown', 10024: 'unknown', 10025: 'unknown', 10082: 'amandaidx',
    10083: 'amidxtape', 10215: 'unknown', 10243: 'unknown',
    10566: 'unknown', 10800: 'gestor', 11111: 'vce', 11371: 'hkp',
    11967: 'unknown', 12000: 'entextxid', 12174: 'unknown',
    12265: 'unknown', 12345: 'netbus', 13456: 'vatata', 13722: 'bpjava-msvc',
    13782: 'netbackup', 13783: 'netbackup', 14000: 'scotty-ft',
    14238: 'palm-net', 14441: 'unknown', 14442: 'unknown',
    15000: 'hydap', 15002: 'onep-tls', 15660: 'bex-xr',
    15742: 'unknown', 16000: 'fmsas', 16001: 'fmsascon', 16012: 'unknown',
    16016: 'unknown', 16018: 'unknown', 16080: 'osxwebadmin',
    16113: 'unknown', 16992: 'unknown', 16993: 'unknown',
    17877: 'unknown', 17988: 'unknown', 18040: 'unknown',
    18101: 'unknown', 18988: 'unknown', 19101: 'unknown',
    19283: 'unknown', 19801: 'unknown', 19999: 'unknown',
    20000: 'dnp', 20005: 'unknown', 20031: 'unknown', 20221: 'unknown',
    20222: 'unknown', 20808: 'unknown', 21571: 'unknown',
    22000: 'unknown', 22222: 'easyengine', 23456: 'unknown',
    24444: 'unknown', 24800: 'unknown', 25000: 'icl-twobase1',
    25576: 'unknown', 26214: 'unknown', 27000: 'flexlm0',
    27001: 'flexlm1', 27002: 'flexlm2', 27003: 'flexlm3',
    27004: 'flexlm4', 27005: 'flexlm5', 27006: 'flexlm6',
    27007: 'flexlm7', 27008: 'flexlm8', 27009: 'flexlm9',
    27015: 'gameranger', 27017: 'mongod', 27018: 'mongod',
    27019: 'mongod', 27715: 'unknown', 28000: 'unknown',
    28119: 'unknown', 30000: 'ndmps', 30718: 'unknown',
    31337: 'elite', 32768: 'filenet-tms', 32769: 'filenet-rpc',
    32770: 'filenet-nch', 32771: 'filenet-rmi', 32772: 'filenet-pa',
    32773: 'filenet-cm', 32774: 'filenet-re', 32775: 'filenet-pch',
    32776: 'filenet-peior', 32777: 'filenet-obrok', 32784: 'unknown',
    32811: 'unknown', 33354: 'unknown', 33389: 'unknown',
    33899: 'unknown', 34571: 'unknown', 34572: 'unknown',
    34573: 'unknown', 35500: 'unknown', 38292: 'unknown',
    40000: 'safetynetp', 40193: 'unknown', 41511: 'unknown',
    42510: 'unknown', 44123: 'unknown', 44443: 'coldfusion-auth',
    44501: 'unknown', 44818: 'etherip', 45100: 'unknown',
    47001: 'winrm', 48080: 'unknown', 49152: 'unknown',
    49153: 'unknown', 49154: 'unknown', 49155: 'unknown',
    49156: 'unknown', 49157: 'unknown', 49158: 'unknown',
    49159: 'unknown', 49160: 'unknown', 49161: 'unknown',
    49162: 'unknown', 49163: 'unknown', 49164: 'unknown',
    49165: 'unknown', 49166: 'unknown', 49167: 'unknown',
    49168: 'unknown', 49169: 'unknown', 49170: 'unknown',
    49171: 'unknown', 49172: 'unknown', 49173: 'unknown',
    49174: 'unknown', 49175: 'unknown', 49176: 'unknown',
    49177: 'unknown', 49178: 'unknown', 49179: 'unknown',
    49180: 'unknown', 49181: 'unknown', 49182: 'unknown',
    49183: 'unknown', 49184: 'unknown', 49185: 'unknown',
    49186: 'unknown', 49187: 'unknown', 49188: 'unknown',
    49189: 'unknown', 49190: 'unknown', 49191: 'unknown',
    49192: 'unknown', 49193: 'unknown', 49194: 'unknown',
    49195: 'unknown', 49196: 'unknown', 49197: 'unknown',
    49198: 'unknown', 49199: 'unknown', 49200: 'unknown',
    50000: 'ibm-db2', 50001: 'unknown', 50002: 'iiimsf',
    50003: 'unknown', 50006: 'unknown', 50300: 'unknown',
    50389: 'unknown', 50500: 'unknown', 50636: 'unknown',
    50800: 'unknown', 51103: 'unknown', 51493: 'unknown',
    52673: 'unknown', 52822: 'unknown', 52848: 'unknown',
    52869: 'unknown', 54045: 'unknown', 54328: 'unknown',
    55055: 'unknown', 55056: 'unknown', 55555: 'unknown',
    55600: 'unknown', 56737: 'unknown', 56738: 'unknown',
    57294: 'unknown', 57797: 'unknown', 58080: 'unknown',
    60020: 'unknown', 60443: 'unknown', 61532: 'unknown',
    62078: 'unknown', 63331: 'unknown', 64623: 'unknown',
    64680: 'unknown', 65000: 'unknown', 65129: 'unknown',
    65389: 'unknown',
}

TIMING_TEMPLATES = {
    0: {'timeout': 10.0, 'max_retries': 3, 'delay': 5.0, 'parallelism': 1, 'host_timeout': 300000, 'scan_delay': 5000},
    1: {'timeout': 5.0, 'max_retries': 2, 'delay': 2.0, 'parallelism': 5, 'host_timeout': 300000, 'scan_delay': 2000},
    2: {'timeout': 2.0, 'max_retries': 2, 'delay': 0.8, 'parallelism': 15, 'host_timeout': 300000, 'scan_delay': 800},
    3: {'timeout': 1.0, 'max_retries': 1, 'delay': 0.4, 'parallelism': 50, 'host_timeout': 0, 'scan_delay': 400},
    4: {'timeout': 0.75, 'max_retries': 1, 'delay': 0.2, 'parallelism': 200, 'host_timeout': 0, 'scan_delay': 200},
    5: {'timeout': 0.5, 'max_retries': 0, 'delay': 0.0, 'parallelism': 1000, 'host_timeout': 0, 'scan_delay': 0},
}

DEFAULT_PROFILES = {
    'quick': {
        'ports': '21,22,23,25,53,80,110,143,443,445,1433,3306,3389,5432,5900,8080,8443',
        'timing': 4,
        'description': 'Top 17 most critical ports - Quick recon (30-60 seconds)'
    },
    'common': {
        'ports': '1-1024',
        'timing': 3,
        'description': 'All common ports under 1024 - Standard scanning (1-3 minutes)'
    },
    'thorough': {
        'ports': '1-65535',
        'timing': 2,
        'description': 'All 65535 ports - Complete picture (2-5 minutes, varies by target)'
    },
    'web': {
        'ports': '80,443,8000,8080,8888,3000,5000,9000,9090,10000',
        'timing': 4,
        'description': 'Web server ports - For website/web service testing'
    },
    'database': {
        'ports': '1433,3306,5432,6379,27017,9200,8086,5984',
        'timing': 3,
        'description': 'Database and cache ports - SQL, NoSQL, search engines'
    },
    'ssh': {
        'ports': '22,2222,22222',
        'timing': 4,
        'description': 'SSH and alternatives - Remote access detection'
    },
}
