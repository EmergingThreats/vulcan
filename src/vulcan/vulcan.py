from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap, conf
from typing import Literal, Union, List
from ipaddress import ip_network
from dataclasses import dataclass
import magic
import random
import re
import constants

from utils import check_port
from logger import get_logger

logger = get_logger(name="vulcan", log_level="DEBUG")


class VulcanSessionManager:
    def __init__(self, packets, file_name):
        self.vulcan_packets = [VulcanPacket(pkt) for pkt in packets]
        self.sessions = []
        self.tcp_state = {}
        self.icmp_state = {}
        self.pcap_file = file_name

    def assemble(self):
        for pkt in self.vulcan_packets:
            if not pkt.stream:
                pkt.stream = random.randint(1000, 10000)

            if pkt.transport_frame.protocol == 'tcp':
                if pkt.autofill:
                    self._process_tcp(pkt)
                else:
                    self.sessions.append(pkt.vpkt)

            elif pkt.transport_frame.protocol == 'udp':
                self.sessions.append(pkt.vpkt)

            elif pkt.transport_frame.protocol == 'icmp':
                if pkt.autofill:
                    self._process_icmp(pkt)
                else:
                    self.sessions.append(pkt.vpkt)

    def _autcomplete_dns(self, pkt):
        pkt.vpkt[Vulcan_DNS].id = pkt.vpkt[Vulcan_DNS].id if pkt.vpkt[Vulcan_DNS].id else random.randint(100,10000)

        # response
        if pkt.vpkt[Vulcan_DNS].qr:
            self.sessions.append(
                Vulcan_Ether(src=pkt.vpkt[Vulcan_Ether].dst, dst=pkt.vpkt[Vulcan_Ether].src) / 
                Vulcan_IP(src=pkt.vpkt[Vulcan_IP].dst, dst=pkt.vpkt[Vulcan_IP].src) /
                Vulcan_UDP(sport=pkt.vpkt[Vulcan_UDP].dport, dport=pkt.vpkt[Vulcan_UDP].sport) /
                Vulcan_DNS(id=pkt.vpkt[Vulcan_DNS].id, qname=pkt.vpkt[Vulcan_DNS].qname, 
                           qtype=pkt.vpkt[Vulcan_DNS].qtype)
            )
            self.sessions.append(pkt.vpkt)

        else:
            self.sessions.append(pkt.vpkt)
            self.sessions.append(
                Vulcan_Ether(src=pkt.vpkt[Vulcan_Ether].dst, dst=pkt.vpkt[Vulcan_Ether].src) / 
                Vulcan_IP(src=pkt.vpkt[Vulcan_IP].dst, dst=pkt.vpkt[Vulcan_IP].src) /
                Vulcan_UDP(sport=pkt.vpkt[Vulcan_UDP].dport, dport=pkt.vpkt[Vulcan_UDP].sport) /
                Vulcan_DNS(id=pkt.vpkt[Vulcan_DNS].id, qname=pkt.vpkt[Vulcan_DNS].qname, 
                           qtype=pkt.vpkt[Vulcan_DNS].qtype, qr=1, answers=["8.8.8.8"])
            )

    def _process_icmp(self, pkt):
        """
        Construct icmp streams.

        stream -> index of self.sessions
        """
        if not pkt.stream or pkt.stream not in self.icmp_state:
            self._initialize_icmp_session(pkt)

    def _initialize_icmp_session(self, pkt):
        """
        Assumes that the ICMP frame added is the request 
        """
        smac, dmac, eth_type_int = pkt.ether_frame.src, pkt.ether_frame.dst, pkt.ether_frame.type
        ip_ver, sip, dip, ip_ttl = pkt.ip_frame.version, pkt.ip_frame.src, pkt.ip_frame.dst, pkt.ip_frame.ttl
        icmp_type, icmp_code, icmp_id, icmp_seq = pkt.transport_frame.type, pkt.transport_frame.code, pkt.transport_frame.id, pkt.transport_frame.seq

        if eth_type_int == 2048:
            eth_type = "ipv4"
        elif eth_type_int == 34525:
            eth_type = "ipv6"
        else: 
            logger.error("ICMP autofill got weird ether type value.")
            raise ValueError("ICMP autofill got weird ether type value.")

        icmp_request_type = 8
        icmp_response_type = 0

        # user submitted request, form response
        if icmp_type == icmp_request_type:
            ether_req = Vulcan_Ether(src=smac, dst=dmac, type=eth_type)
            ip_req = Vulcan_IP(version=ip_ver, src=sip, dst=dip, ttl=ip_ttl)
            icmp_req = Vulcan_ICMP(type=icmp_request_type, code=icmp_code, id=icmp_id, seq=icmp_seq)

            ether_reply = Vulcan_Ether(src=dmac, dst=smac, type=eth_type)
            ip_reply = Vulcan_IP(version=ip_ver, src=dip, dst=sip)
            icmp_reply = Vulcan_ICMP(type=icmp_response_type, code=icmp_code, id=icmp_id, seq=icmp_seq)

            self.sessions.append(ether_req / ip_req / icmp_req)
            self.sessions.append(ether_reply / ip_reply / icmp_reply)

        # user submitted response, form request
        elif icmp_type == icmp_response_type:
            ether_req = Vulcan_Ether(src=dmac, dst=smac, type=eth_type)
            ip_req = Vulcan_IP(version=ip_ver, src=dip, dst=sip)
            icmp_req = Vulcan_ICMP(type=icmp_request_type, code=icmp_code, id=icmp_id, seq=icmp_seq)

            ether_reply = Vulcan_Ether(src=smac, dst=dmac, type=eth_type)
            ip_reply = Vulcan_IP(version=ip_ver, src=sip, dst=dip, ttl=ip_ttl)
            icmp_reply = Vulcan_ICMP(type=icmp_response_type, code=icmp_code, id=icmp_id, seq=icmp_seq)

            self.sessions.append(ether_req / ip_req / icmp_req)
            self.sessions.append(ether_reply / ip_reply / icmp_reply)
        else:
            logger.warning(f'ICMP Type ({icmp_type}) unexpected.')

            ether_unknown = Vulcan_Ether(src=smac, dst=dmac, type=eth_type)
            ip_unknown = Vulcan_IP(version=ip_ver, src=sip, dst=dip)
            icmp_unknown = Vulcan_ICMP(
                type=icmp_type,
                code=icmp_code if icmp_code is not None else Vulcan_ICMP().code,
                id=icmp_id if icmp_id is not None else Vulcan_ICMP().id,
                seq=icmp_seq if icmp_seq is not None else Vulcan_ICMP().seq
            )

            self.sessions.append(ether_unknown / ip_unknown / icmp_unknown)


    def _process_tcp(self, pkt):
        """ Construct tcp streams. """
        if not self.tcp_state:
            self._initialize_tcp_session(pkt)
        else:
            if pkt.stream not in self.tcp_state:
                self._close_tcp_session()
                self._initialize_tcp_session(pkt)

        self._continue_tcp_session(pkt)

    def _initialize_tcp_session(self, pkt):
        """ 3 way handshake """
        sport, dport = pkt.transport_frame.sport, pkt.transport_frame.dport

        # syn
        syn = Vulcan_TCP(sport=sport, dport=dport, seq=0, ack=0, flags="S", window=65535)
        self.sessions.append(pkt.ether_frame / pkt.ip_frame / syn)

        # syn/ack
        synack = Vulcan_TCP(sport=dport, dport=sport, seq=0, ack=syn.seq+1, flags="SA", window=65535)
        self.sessions.append(
            Vulcan_Ether(pkt.ether_frame.dst, pkt.ether_frame.src) /
            Vulcan_IP(src=pkt.ip_frame.dst, dst=pkt.ip_frame.src) /
            synack
        )

        # ack
        ack = Vulcan_TCP(sport=sport, dport=dport, seq=syn.seq+1, ack=synack.seq+1, flags="A")
        self.sessions.append(pkt.ether_frame / pkt.ip_frame / ack)

        self.tcp_state[pkt.stream] = {'sport': sport, 'dport': dport, 'client': {'seq': ack.seq, 'ack': ack.ack}, 'server': {'seq': ack.ack, 'ack': ack.seq}}

    def _continue_tcp_session(self, pkt):
        """ Process next vulcan packet """

        stream = pkt.stream
        direction = "client" if pkt.transport_frame.sport == self.tcp_state[stream]['sport'] else "server"
        opposite = "server" if direction == "client" else "client"

        pkt.vpkt[Vulcan_TCP].seq = self.tcp_state[stream][direction]['seq']
        pkt.vpkt[Vulcan_TCP].ack = self.tcp_state[stream][opposite]['seq']
        self.sessions.append(pkt.vpkt)

        payload_length = len(pkt.vpkt[Raw].load) if Raw in pkt.vpkt else 0

        self.tcp_state[stream][direction]['seq'] += payload_length
        self.tcp_state[stream][opposite]['ack'] += payload_length

        self._ack_packet(pkt)

    def _ack_packet(self, pkt):
        """ Ack payload receipt """
        stream = pkt.stream
        direction = "client" if pkt.transport_frame.sport == self.tcp_state[stream]['sport'] else "server"
        opposite = "server" if direction == "client" else "client"

        if direction == 'client':
            sport = pkt.transport_frame.dport
            dport = pkt.transport_frame.sport
            ether_ip = (
                Vulcan_Ether(pkt.ether_frame.dst, pkt.ether_frame.src) /
                Vulcan_IP(src=pkt.ip_frame.dst, dst=pkt.ip_frame.src)
            )

        else:
            sport = pkt.transport_frame.sport
            dport = pkt.transport_frame.dport
            ether_ip = (pkt.ether_frame / pkt.ip_frame)

        ack = Vulcan_TCP(
            sport=sport,
            dport=dport,
            seq=self.tcp_state[stream][opposite]['seq'],
            ack=self.tcp_state[stream][direction]['seq'],
            flags="A"
        )

        self.sessions.append(ether_ip / ack)
        self.tcp_state[stream][direction]['ack'] = ack.seq

        logger.debug(f"[Stream {stream}] {ack.sport} -> {ack.dport} A seq={ack.seq} ack={ack.ack} len={len(ack.payload)}")
        logger.debug(f"[Stream {stream}] {self.tcp_state}")
        self.previous_pkt = pkt

    def _close_tcp_session(self):
        """ Closing session packets """
        stream = self.previous_pkt.stream
        finack = Vulcan_TCP(sport=self.previous_pkt.transport_frame.sport, 
                            dport=self.previous_pkt.transport_frame.dport, 
                            seq=self.tcp_state[stream]['client']['seq'], 
                            ack=self.tcp_state[stream]['server']['seq'], 
                            flags="FA")
        ack = Vulcan_TCP(sport=self.previous_pkt.transport_frame.dport, 
                            dport=self.previous_pkt.transport_frame.sport, 
                            seq=self.tcp_state[stream]['server']['seq'] + 1, 
                            ack=self.tcp_state[stream]['client']['seq'] + 1, 
                            flags="A")

        self.sessions.append(self.previous_pkt.ether_frame / self.previous_pkt.ip_frame / finack)
        self.sessions.append(
            Vulcan_Ether(self.previous_pkt.ether_frame.dst, self.previous_pkt.ether_frame.src) /
            Vulcan_IP(src=self.previous_pkt.ip_frame.dst, dst=self.previous_pkt.ip_frame.src) /
            ack
        )

        logger.debug(f"[Stream {stream}] {finack.sport} -> {finack.dport} FA seq={finack.seq} ack={finack.ack}")
        logger.debug(f"[Stream {stream}] {ack.sport} -> {ack.dport} A seq={ack.seq} ack={ack.ack}")
        logger.debug(f"[Stream {stream}] {self.tcp_state}")

    def write_cap(self):
        # print(self.sessions)
        sessions = []
        timestamp = 0
        for p in self.sessions:
            p.time = timestamp
            timestamp += random.random()
            sessions.append(p)

        wrpcap(self.pcap_file, sessions)


class VulcanPacket:
    def __init__(self, packet: dict):
        self.packet = packet
        self.ether_frame = None
        self.ip_frame = None
        self.transport_frame = None
        self.application_frame = None
        self._payload = None
        self.stream = packet.get('stream', {}).get('id')
        self.autofill = packet.get('autofill', {}).get('enabled', False)
        self.build_frames()
        self.assemble()

    def build_frames(self):
        # build ethernet frame
        if self.packet.get('ether'):
            self.ether_frame = Vulcan_Ether(**self.packet.get('ether'))
        else:
            if self.autofill:
                self.ether_frame = Vulcan_Ether()
            else: 
                logger.error("Missing ETH frame.")
                raise ValueError("Missing ETH frame.")

        # build ip frame (IPv4 or IPv6)
        if self.packet.get('ip'):
            self.ip_frame = Vulcan_IP(**self.packet.get('ip'))
        else:
            if self.autofill:
                self.ip_frame = Vulcan_IP()
            else:
                logger.error("Missing IP frame.")
                raise ValueError("Missing IP frame.")

        # build transport frame (TCP, UDP, ICMP)
        if self.packet.get('tcp'):
            self.transport_frame = Vulcan_TCP(**self.packet.get('tcp'))
        elif self.packet.get('udp'):
            self.transport_frame = Vulcan_UDP(**self.packet.get('udp'))
        elif self.packet.get('icmp'):
            self.transport_frame = Vulcan_ICMP(**self.packet.get('icmp'))

        # build application frame (HTTP request/response, etc.)
        if self.packet.get('http_request'):
            if self.autofill and not self.transport_frame:
                self.transport_frame = Vulcan_TCP()

            self.application_frame = VulcanHTTPRequest(**self.packet.get('http_request')).build_request()
        elif self.packet.get('http_response'):
            if self.autofill and not self.transport_frame:
                self.transport_frame = Vulcan_TCP()

            self.application_frame = VulcanHTTPResponse(**self.packet.get('http_response')).build_response()
        elif self.packet.get('dns'):
            if self.autofill and not self.transport_frame:
                self.transport_frame = Vulcan_UDP()

            self.application_frame = Vulcan_DNS(**self.packet.get('dns'))

        # raw payloads
        payload = self.packet.get('raw', {}).get('payload')
        if payload:
            if self.autofill and not self.transport_frame:
                self.transport_frame = Vulcan_TCP()

            hex_pattern = re.compile(r"^((\\x|0x)?[a-fA-F0-9]{2}\s?)+$")
            if bool(hex_pattern.match(payload)):
                extracted_hex = re.findall(r"(?:\\x|0x)?([a-fA-F0-9]{2})[\s,]?", payload)
                self._payload = bytes.fromhex(''.join(extracted_hex))
            else:
                if '\\r' in payload:
                    payload = payload.replace('\\r', '\r')
                if '\\n' in payload:
                    payload = payload.replace('\\n', '\n')

                payload = re.sub(r'(?<!\r)\n', '\r\n', payload)

                self._payload = payload.encode()

    def assemble(self):
        # Assemble packet based on available frames
        if self.ether_frame:
            self.vpkt = self.ether_frame

            if self.ip_frame:
                self.vpkt /= self.ip_frame

                if self.transport_frame:
                    self.vpkt /= self.transport_frame

                    if self.application_frame:
                        self.vpkt /= self.application_frame

        if self._payload:
            self.vpkt /= Raw(load=self._payload)


# trying to have most of the values be optional so that people can just enter what they need
class Vulcan_Ether(Ether):
    """
    MAC inputs
    - by selection (VMware [00:05:69:xx:xx:xx], Broadcom [00:05:B5:xx:xx:xx])
    - by input
    """
    def __init__(self, 
                 src: str = "00:1b:44:11:3a:b7",
                 dst: str = "2c:54:91:88:c9:e3", 
                 type: str = "ipv4",
                 **kwargs):

        if src.lower() in constants.MAC_ADDRESS.keys():
            src = self._generate_mac(constants.MAC_ADDRESS[src.lower()])

        if dst.lower() in constants.MAC_ADDRESS.keys():
            dst = self._generate_mac(constants.MAC_ADDRESS[dst.lower()])

        for loc in [src, dst]:
            if not self._valid_mac(loc):
                logger.error(f"Invalid MAC address format: {loc}")
                raise ValueError(f"Invalid MAC address format: {loc}")

        if type.lower() not in constants.ETHER_TYPES.keys():
            logger.error(f"Unsupported Ether Type ({type}). Only valid options: IPv4, IPv6")
            raise ValueError(f"Unsupported Ether Type ({type}). Only valid options: IPv4, IPv6")

        super().__init__(src=src, dst=dst, type=constants.ETHER_TYPES.get(type.lower()), **kwargs)

    def _valid_mac(self, mac: str):
        mac_pattern = re.compile(r"^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$")
        return bool(mac_pattern.match(mac))

    def _generate_mac(self, prefix: str):
        return prefix + ":" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))

conf.l2types.register(1, Vulcan_Ether)

class Vulcan_IP(IP):
    """
    IP inputs
    - by selection ($HOME_NET, $EXTERNAL_NET, any)
    - by input (IP, CIDR)
    """
    protocol = 'ip'

    def __init__(self, 
                 version: Literal[4, 6] = 4,
                 src: str = "$home_net",
                 dst: str = "$home_net", 
                 ttl: int = 64,
                 **kwargs):
        try:
            version_int = int(version)
        except ValueError as e:
            logger.error(f'Unsupported Ip Version ({version}). Must be int. {e}')
            raise ValueError(f'Unsupported Ip Version ({version}). Must be int. {e}')

        if version_int == 4:
            dst = self._process_ipv4(dst)
            src = self._process_ipv4(src)
        elif version_int == 6:
            dst = self._process_ipv6(dst)
            src = self._process_ipv6(src)
        else:
            logger.error(f"Unsupported IP Version ({version}): Only supporting versions 4 or 6.")
            raise ValueError(f"Unsupported IP Version ({version}): Only supporting versions 4 or 6.")

        try:
            ttl_int = int(ttl)
        except ValueError as e:
            logger.error(f'Invalid TTL Value. Must be an int: {e}')
            raise ValueError(f'Invalid TTL Value. Must be an int: {e}')
        if not (0 <= ttl_int <= 255):
            logger.error("Invalid TTL Value. Must be < 255")
            raise ValueError(f"Invalid TTL Value. Must be < 255")

        super().__init__(src=src, dst=dst, ttl=ttl_int, **kwargs)

    def _process_ipv4(self, value: str):
        if value.lower() == '$home_net':
            return self._random_ip(private=True)

        if value.lower() in ['$external_net', 'any']:
            return self._random_ip()

        cidr_pattern = re.compile(r"^(\d+\.){3}\d+\/\d+$")
        if bool(cidr_pattern.match(value)):
            network = ip_network(value)
            return str(network[random.randint(1, network.num_addresses - 2)])

        if not self._valid_ip(value):
            logger.error(f"Invalid IP ($HOME_NET, $EXTERNAL_NET, any, <IP>, <CIDR>): {value}")
            raise ValueError(f"Invalid IP ($HOME_NET, $EXTERNAL_NET, any, <IP>, <CIDR>): {value}")

        return value

    # TODO add ipv6 handling
    def _process_ipv6(self, value: str):
        pass

    def _valid_ip(self, ip: str):
        ip_pattern = re.compile(r"^(\d+\.){3}\d+$")
        return bool(ip_pattern.match(ip))

    def _random_ip(self, private: bool = False):
        if private:
            block_choice = random.choice(['10', '172', '192'])
            if block_choice == '10':
                return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
            elif block_choice == '172':
                return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
            else:
                return f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        else:
            return ".".join(map(str, (random.randint(1, 255) for _ in range(4))))


class Vulcan_TCP(TCP):
    """
    Ports inputs (src/dst)
    - by selection ($VARIABLE, any)
        - $HTTP_PORTS = 80,443,8080,8443
        - $SMTP_PORTS = 25,589
    - by input (1-65535)
    """
    protocol = 'tcp'

    def __init__(self, 
                    sport: Union[int, str] = 'any', 
                    dport: Union[int, str] = 80, 
                    seq: int = 1,
                    ack: int = 1,
                    flags: str = "PA", # maybe we just have this come in as "SYN", "ACK"...? 
                    window: int = 8192,
                    **kwargs):

        try:
            sport = check_port(sport)
            dport = check_port(dport)
        except ValueError as e:
            logger.error(e)
            raise ValueError(e)

        if not self._check_flags(flags):
            logger.error(f'Invalid TCP flag: {flags}')
            raise ValueError(f"Invalid TCP flag: {flags}.")
        try: 
            seq_int = int(seq)
        except ValueError:
            logger.error("Invalid TCP Seq value. Must be int.")
            raise ValueError("Invalid TCP Seq value. Must be int.")

        try: 
            ack_int = int(ack)
        except ValueError:
            logger.error("Invalid TCP Ack value. Must be int.")
            raise ValueError("Invalid TCP Ack value. Must be int.")

        try: 
            window_int = int(window)
        except ValueError:
            logger.error("Invalid TCP Window value. Must be int.")
            raise ValueError("Invalid TCP Window value. Must be int.")

        super().__init__(sport=sport, dport=dport, seq=seq_int, ack=ack_int, flags=flags, window=window_int, **kwargs)

    def _check_flags(self, flags: str):
        flags_pattern = re.compile(r"^[SAFRPU]+$")
        return bool(flags_pattern.match(flags))


class Vulcan_UDP(UDP):
    """
    Ports inputs (src/dst)
    - by selection ($VARIABLE, any)
        - $HTTP_PORTS = 80,443,8080,8443
        - $SMTP_PORTS = 25,589
    - by input (1-65535)
    """
    protocol = 'udp'

    def __init__(self, 
                    sport: Union[int, str] = 'any',
                    dport: Union[int, str] = 53,
                    **kwargs):

        try:
            sport = check_port(sport)
            dport = check_port(dport)
        except ValueError as e:
            logger.error(e)
            raise ValueError(e)

        super().__init__(sport=sport, dport=dport, **kwargs)


class Vulcan_ICMP(ICMP):
    protocol = 'icmp'

    def __init__(self, 
                    type: int = 8, 
                    code: int = 1, 
                    id: int = 1,
                    seq: int = 1,
                    **kwargs):

        try:
            type_int = int(type)
        except ValueError:
            logger.error("Invalid ICMP Type value. Must be int.")
            raise ValueError("Invalid ICMP Type value. Must be int.")

        try:
            code_int = int(code)
        except ValueError:
            logger.error("Invalid ICMP Code value. Must be int.")
            raise ValueError("Invalid ICMP Code value. Must be int.")

        try: 
            id_int = int(id)
        except ValueError:
            logger.error("Invalid ICMP ID value. Must be int.")
            raise ValueError("Invalid ICMP ID value. Must be int.")

        try: 
            seq_int = int(seq)
        except ValueError:
            logger.error("Invalid ICMP Seq value. Must be int.")
            raise ValueError("Invalid ICMP Seq value. Must be int.")

        if not type_int <= 43:
            logger.error(f'Invalid ICMP Type({type})')
            raise ValueError(f"Invalid ICMP Type ({type})")

        if not code_int <= 15:
            logger.error(f'Invalid ICMP Code ({code})')
            raise ValueError(f"Invalid ICMP Code ({code})")

        super().__init__(type=type_int, code=code_int, id=id_int, seq=seq_int, **kwargs)


class Vulcan_DNS(DNS):
    protocol = 'dns'

    def __init__(self,
                    qname: str = "example.com", # query name
                    qtype: str = 'A',           # query type (A, AAAA, CNAME, NS, PTR, RRSIG, SIG, SOA, TXT)
                    rd: int = 1,                # recursion
                    qr: int = 0,                # query response (0 = query, 1 = response)
                    answers: List[str] = [],    # query answers: A Record -> ["179.23.99.1"]
                    **kwargs):

        try: 
            rd_int = int(rd)
        except ValueError:
            logger.error("Invalid DNS rd value. Must be int.")
            raise ValueError("Invalid DNS rd value. Must be int.")

        try: 
            qr_int = int(qr)
        except ValueError:
            logger.error("Invalid DNS qr value. Must be int.")
            raise ValueError("Invalid DNS qr value. Must be int.")

        if not qr_int:
            super().__init__(qr=qr_int, rd=rd_int, qd=DNSQR(qname=qname, qtype=qtype), **kwargs)
        else:
            if not answers:
                logger.error("DNS Answers Empty.")
                raise ValueError("DNS Answers Empty.")

            if isinstance(answers, str):
                answers_list = answers.split(',')
            elif isinstance(answers, list):
                answers_list = answers
            else: 
                logger.error("Invalid DNS Answers value. Must be list or comma delimited str.")
                raise ValueError("Invalid DNS Answers value. Must be list or comma delimited str.")

            answer_records = [DNSRR(rrname=qname, type=qtype, rdata=answer) for answer in answers_list]
            super().__init__(qr=1, rd=rd_int, qd=DNSQR(qname=qname, qtype=qtype), ancount=len(answer_records), an=answer_records, **kwargs)


@dataclass
class VulcanHTTPRequest:
    headers: dict
    method: Literal['GET', 'POST', 'PUT', 'get', 'post', 'put'] = "GET"
    path: str = "/"
    version: Literal["1.0", "1.1", "2"] = "1.1"
    body: str = None
    tls_enabled: bool = False
    protocol: str = 'http'

    def _detect_content_type(self):
        mime = magic.Magic(mime=True)
        return mime.from_buffer(self.body)

    def build_request(self):
        self.request = f"{self.method} {self.path} HTTP/{self.version}\r\n"

        if self.headers:
            if isinstance(self.headers, str):
                self.headers = {header.split(':')[0] : header.split(':')[1] for header in self.headers.split('|') }
            elif not isinstance(self.headers, dict):
                logger.error("Invalid HTTP Response Header value. Must be str or JSON.")
                raise ValueError("Invalid HTTP Response Header value. Must be str or JSON.")

        if self.version == '2':
            self.request += '\r\n'.join(f"{k.lower()}: {v}" for k, v in self.headers.items()) + '\r\n'

        else:
            self.request += '\r\n'.join(f"{k}: {v}" for k, v in self.headers.items()) + '\r\n'

        if self.body:
            if not self.headers.get('Content-Type'):
                self.request += f"Content-Type: {self._detect_content_type()}\r\n"

            self.request += f"Content-Length: {len(self.body)}\r\n"
            self.request += '\r\n' + self.body
        else:
            self.request += '\r\n'

        return Raw(load=self.request)


@dataclass
class VulcanHTTPResponse:
    headers: dict
    code: int = 200
    reason: str = "OK"
    version: Literal["1.0", "1.1", "2"] = "1.1"
    body: str = None
    tls_enabled: bool = False
    protocol: str = 'http'

    def _detect_content_type(self):
        mime = magic.Magic(mime=True)
        return mime.from_buffer(self.body)

    def build_response(self):
        self.response = f"HTTP/{self.version} {self.code} {self.reason}\r\n"
        if self.headers:
            if isinstance(self.headers, str):
                self.headers = {header.split(':')[0] : header.split(':')[1] for header in self.headers.split('|') }
            elif not isinstance(self.headers, dict):
                logger.error("Invalid HTTP Response Header value. Must be str or JSON.")
                raise ValueError("Invalid HTTP Response Header value. Must be str or JSON.")

            if self.version == '2':
                self.response += '\r\n'.join(f"{k.lower()}: {v}" for k, v in self.headers.items()) + '\r\n'

            else:
                self.response += '\r\n'.join(f"{k}: {v}" for k, v in self.headers.items()) + '\r\n'

        if self.body:
            if not self.headers.get('Content-Type'):
                self.response += f"Content-Type: {self._detect_content_type()}\r\n"

            self.response += f"Content-Length: {len(self.body)}\r\n"
            self.response += '\r\n' + self.body
        else:
            self.response += "Content-Length: 0\r\n\r\n"

        return Raw(load=self.response)
