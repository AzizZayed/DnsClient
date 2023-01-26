from enum import Enum
import random
from typing import List, Tuple, Dict

HEADER_SIZE: int = 12


def encode_domain_name(domain_name: str) -> bytes:
    """
    Encode domain name into bytes
    :return: encoded domain name
    """
    encoded_domain_name: bytes = b""
    for label in domain_name.split("."):
        encoded_domain_name += len(label).to_bytes(1, "big")
        encoded_domain_name += label.encode("ascii")
    encoded_domain_name += b"\x00"

    return encoded_domain_name


def decode_domain_name(encoded_domain_name: bytes, start_index: int, domain_cache=None) -> Tuple[str, int]:
    """
    Decode domain name from bytes
    :param encoded_domain_name: encoded domain name
    :param start_index: index to start decoding from in the encoded data
    :param domain_cache: cache of previously decoded domain names
    :return: decoded domain name
    """

    # TODO: major bug here, need to fix when EXCHANGE section points to original offset in response packet

    if domain_cache is None:
        domain_cache = {}

    domain_name: str = ""
    index: int = start_index
    while encoded_domain_name[index] != 0:
        if encoded_domain_name[index] & 0xC0 == 0xC0:
            # Compression case
            offset: int = int.from_bytes(encoded_domain_name[index:index + 2], "big") & 0x3FFF
            if offset in domain_cache:
                domain_name += domain_cache[offset]
            else:
                domain_name += decode_domain_name(encoded_domain_name, offset, domain_cache)[0]
            index += 1
            break
        else:
            # Regular case
            label_length: int = encoded_domain_name[index]
            index += 1
            domain_name += encoded_domain_name[index:index + label_length].decode("ascii") + "."
            index += label_length

    # Remove trailing dot
    if domain_name[-1] == ".":
        domain_name = domain_name[:-1]

    if start_index not in domain_cache:
        domain_cache[start_index] = domain_name

    return domain_name, index + 1


class QType(Enum):
    """Enum for DNS query types with their corresponding values"""
    A = 0x0001
    NS = 0x0002
    MX = 0x000f
    CNAME = 0x0005
    OTHER = 0x0000


class Request:
    """DNS request class"""

    def __init__(self, domain_name: str, query_type: QType):
        self.domain_name: str = domain_name
        self.query_type: QType = query_type

    def to_bytes(self) -> bytes:
        """
        Convert request to bytes. The request header is formatted as follows:
        2 bytes: Transaction ID
        2 bytes: Flags (QR, OPCODE, AA, TC, RD, RA, Z, RCODE)
        2 bytes: Number of questions
        2 bytes: Number of answers
        2 bytes: Number of authority records
        2 bytes: Number of additional records

        | Transaction ID | Flags | Questions | Answers | Authority | Additional |
        |----------------|-------|-----------|---------|-----------|------------|
        | 2 bytes        | 2     | 2         | 2       | 2         | 2          |

        Then the question section is formatted as follows:
        N bytes: Domain name (QNAME)
        2 bytes: Query type (QTYPE)
        2 bytes: Query class (QCLASS)

        :return: byte representation of the request
        """

        # Create DNS request header
        random_id: int = random.getrandbits(16)  # 16-bit random ID
        flags: int = 0x0100  # RD = 1 means recursion desired
        question_count: int = 0x0001  # Number of questions
        answer_count: int = 0x0000  # Number of answers
        authority_count: int = 0x0000  # Number of authority records
        additional_count: int = 0x0000  # Number of additional records

        # Create DNS request question
        qname: bytes = encode_domain_name(domain_name=self.domain_name)
        qtype: int = self.query_type.value
        qclass: int = 0x0001  # Internet

        # Create DNS request packet buffer
        request: bytes = random_id.to_bytes(2, "big")
        request += flags.to_bytes(2, "big")
        request += question_count.to_bytes(2, "big")
        request += answer_count.to_bytes(2, "big")
        request += authority_count.to_bytes(2, "big")
        request += additional_count.to_bytes(2, "big")
        request += qname
        request += qtype.to_bytes(2, "big")
        request += qclass.to_bytes(2, "big")

        return request


class Record:
    """DNS resource record class"""

    def __init__(self, name: str, qtype: QType, class_: int, ttl: int, rdlength: int, rdata: bytes,
                 authoritative: bool):
        self.name: str = name
        self.qtype: QType = qtype
        self.class_: int = class_
        self.ttl: int = ttl
        self.rdlength: int = rdlength
        self.rdata: bytes = rdata
        self.authoritative: bool = authoritative

    def __str__(self) -> str:
        auth_str: str = "auth" if self.authoritative else "noauth"
        if self.qtype == QType.A:
            ip_address: str = ".".join([str(b) for b in self.rdata])
            return f"IP\t\t{ip_address}\t\t{self.ttl}\t\t{auth_str}"
        elif self.qtype == QType.NS:
            server_name: str = decode_domain_name(self.rdata, 0)[0]  # TODO: major error here
            return f"NS\t\t{server_name}\t\t{self.ttl}\t\t{auth_str}"
        elif self.qtype == QType.CNAME:
            alias: str = self.rdata.decode("ascii")
            return f"CNAME\t\t{alias}\t\t{self.ttl}\t\t{auth_str}"
        elif self.qtype == QType.MX:
            preference: int = int.from_bytes(self.rdata[0:2], "big")
            exchange: str = decode_domain_name(self.rdata, 2)[0]  # TODO: major error here
            return f"MX\t\t{exchange}\t\t{preference}\t\t{self.ttl}\t\t{auth_str}"
        else:
            return f"OTHER {self.qtype.name}\t{self.rdata}\t{self.ttl}\t\t{auth_str}"

    def __repr__(self) -> str:
        return self.__str__()


class Response:
    """DNS response class"""

    def __init__(self, response_bytes: bytes):
        self.response_bytes: bytes = response_bytes
        self.id: int = 0
        self.flags: int = 0
        self.authoritative: bool = False
        self.rcode: int = 0
        self.question_count: int = 1
        self.answer_count: int = 0
        self.answer_records: List[Record] = []
        self.additional_count: int = 0
        self.additional_records: List[Record] = []

        self.parse()

    def parse(self):
        """Parse response bytes"""

        self.id = int.from_bytes(self.response_bytes[0:2], "big")
        self.flags = int.from_bytes(self.response_bytes[2:4], "big")
        self.authoritative = bool(self.flags & 0x0400)
        self.rcode = self.flags & 0x000F
        self.question_count = int.from_bytes(self.response_bytes[4:6], "big")
        self.answer_count = int.from_bytes(self.response_bytes[6:8], "big")
        self.additional_count = int.from_bytes(self.response_bytes[10:12], "big")

        offset: int = HEADER_SIZE
        domain_name_cache: Dict[int, str] = {}  # Cache of domain names at offset to avoid parsing them multiple times
        qname, offset = decode_domain_name(self.response_bytes, offset, domain_name_cache)

        offset += 4  # Skip QTYPE and QCLASS for question section

        # Parse records in answer section and additional section (skip authority section)
        offset = self.parse_section(offset, self.answer_count, self.answer_records, domain_name_cache)
        self.parse_section(offset, self.additional_count, self.additional_records, domain_name_cache)

    def parse_section(self, offset: int, count: int, records_list: List[Record], domain_cache: Dict[int, str]) -> int:
        """
        Parse a records section
        :param offset: offset to start parsing from
        :param count: number of records to parse
        :param records_list: list to append parsed records to
        :param domain_cache: cache of domain names to avoid parsing them multiple times
        :return: offset after parsing
        """

        for _ in range(count):
            name, offset = decode_domain_name(self.response_bytes, offset, domain_cache)
            qtype = QType(int.from_bytes(self.response_bytes[offset:offset + 2], "big"))
            class_ = int.from_bytes(self.response_bytes[offset + 2:offset + 4], "big")
            ttl = int.from_bytes(self.response_bytes[offset + 4:offset + 8], "big")
            rdlength = int.from_bytes(self.response_bytes[offset + 8:offset + 10], "big")
            rdata = self.response_bytes[offset + 10:offset + 10 + rdlength]

            offset += 10 + rdlength

            record: Record = Record(name, qtype, class_, ttl, rdlength, rdata, self.authoritative)
            records_list.append(record)

        return offset

    def print(self):
        if self.answer_count > 0:
            print(f"***Answer Section ({self.answer_count} records)***")
            for record in self.answer_records:
                print(record)

        if self.additional_count > 0:
            print(f"***Additional Section ({self.additional_count} records)***")
            for record in self.additional_records:
                print(record)

        if self.answer_count == 0 and self.additional_count == 0:
            print("NOTFOUND")
