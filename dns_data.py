from enum import Enum
import random
from typing import List, Tuple, Dict

from DnsError import FormatError, ServerFailure, NotImplement, Refused

HEADER_SIZE: int = 12


def encode_int(int_to_encode: int, size: int = 2) -> bytes:
    """
    Encode int into bytes
    :param int_to_encode: int to encode
    :param size: size of the encoded int.
    :return: encoded int
    """
    return int_to_encode.to_bytes(size, "big")


def decode_int(encoded_int: bytes) -> int:
    """
    Decode int from bytes
    :param encoded_int: encoded int
    :return: decoded int
    """
    return int.from_bytes(encoded_int, "big")


def encode_domain_name(domain_name: str) -> bytes:
    """
    Encode domain name into bytes
    Example: "www.google.com" -> b"\x03www\x06google\x03com\x00"
    :return: encoded domain name
    """
    encoded_domain_name: bytes = b""
    for label in domain_name.split("."):
        encoded_domain_name += encode_int(len(label), 1)
        encoded_domain_name += label.encode("ascii")
    encoded_domain_name += b"\x00"

    return encoded_domain_name


def decode_domain_name(encoded_domain_name: bytes, start_index: int, domain_cache=None) -> Tuple[str, int]:
    """
    Decode domain name from bytes + handle compression case (pointer)
    :param encoded_domain_name: encoded domain name
    :param start_index: index to start decoding from in the encoded data
    :param domain_cache: cache of previously decoded domain names
    :return: decoded domain name and the index of the next byte to decode
    """

    if domain_cache is None:
        domain_cache = {}

    domain_name: str = ""
    index: int = start_index
    while encoded_domain_name[index] != 0:
        if encoded_domain_name[index] & 0xC0 == 0xC0:  # Compression case
            offset: int = decode_int(encoded_domain_name[index:index + 2]) & 0x3FFF
            if offset in domain_cache:
                domain_name += domain_cache[offset]
            else:
                domain_name += decode_domain_name(encoded_domain_name, offset, domain_cache)[0]
            index += 1
            break
        else:  # Regular case
            label_length: int = encoded_domain_name[index]
            index += 1
            domain_name += encoded_domain_name[index:index + label_length].decode("ascii") + "."
            index += label_length

    # Remove trailing dot
    if domain_name and domain_name[-1] == ".":
        domain_name = domain_name[:-1]

    if start_index not in domain_cache:
        domain_cache[start_index] = domain_name

    return domain_name, index + 1


class QueryType(Enum):
    """Enum for DNS query types with their corresponding values"""

    A = 0x0001
    NS = 0x0002
    MX = 0x000f
    CNAME = 0x0005
    OTHER = 0x0000


class Request:
    """DNS request class"""

    def __init__(self, domain_name: str, query_type: QueryType):
        self.domain_name: str = domain_name
        self.query_type: QueryType = query_type

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
        N bytes: Domain name (QNAME), N means variable length
        2 bytes: Query type (QTYPE)
        2 bytes: Query class (QCLASS)

        | QNAME | QTYPE | QCLASS |
        |-------|-------|--------|
        | N     | 2     | 2      |

        The domain name is to be encoded as a list of labels, each prefixed with its length.

        We leave the answer, authority and additional sections empty.

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
        request: bytes = encode_int(random_id)
        request += encode_int(flags)
        request += encode_int(question_count)
        request += encode_int(answer_count)
        request += encode_int(authority_count)
        request += encode_int(additional_count)
        request += qname
        request += encode_int(qtype)
        request += encode_int(qclass)

        return request


class Record:
    """
    DNS resource record class

    The resource record is formatted as follows:
    N bytes: Domain name (NAME)
    2 bytes: Type (TYPE)
    2 bytes: Class (CLASS)
    4 bytes: Time to live (TTL)
    2 bytes: Data length (RDLENGTH)
    K bytes: Data (RDATA)

    | NAME | TYPE | CLASS | TTL | RDLENGTH | RDATA |
    |------|------|-------|-----|----------|-------|
    | N    | 2    | 2     | 4   | 2        | K     |

    NAME is encoded similar to the domain name in the question section.
    RDATA is encoded according to the type.

    If the type is A, then RDATA is a 4-byte IPv4 address.
    If the type is NS, then RDATA is an encoded domain name.
    If the type is MX, then RDATA is a 2-byte preference value followed by an encoded domain name.
    If the type is CNAME, then RDATA is a n alias.

    """

    def __init__(self, response: bytes, start_index: int, domain_cache: Dict[int, str], authoritative: bool):
        self.response: bytes = response
        self.domain_cache: Dict[int, str] = domain_cache
        self.authoritative: bool = authoritative

        self.name, offset = decode_domain_name(response, start_index, domain_cache)
        self.qtype: QueryType = QueryType(decode_int(response[offset:offset + 2]))
        self.class_: int = decode_int(response[offset + 2:offset + 4])  # TODO throw error if not 1
        self.ttl: int = decode_int(response[offset + 4:offset + 8])

        self.rdlength: int = decode_int(response[offset + 8:offset + 10])
        self.rdata: bytes = response[offset + 10:offset + 10 + self.rdlength]
        self.rdata_offset: int = offset + 10

        self.end_index: int = self.rdata_offset + self.rdlength

    def __str__(self) -> str:
        auth_str: str = "auth" if self.authoritative else "noauth"
        if self.qtype == QueryType.A:
            ip_address: str = ".".join([str(byte) for byte in self.rdata])
            return f"IP\t\t{ip_address}\t\t{self.ttl}\t\t{auth_str}"
        elif self.qtype == QueryType.NS:
            server_name: str = decode_domain_name(self.response, self.rdata_offset, self.domain_cache)[0]
            return f"NS\t\t{server_name}\t\t{self.ttl}\t\t{auth_str}"
        elif self.qtype == QueryType.CNAME:
            alias: str = decode_domain_name(self.response, self.rdata_offset, self.domain_cache)[0]
            return f"CNAME\t\t{alias}\t\t{self.ttl}\t\t{auth_str}"
        elif self.qtype == QueryType.MX:
            preference: int = decode_int(self.rdata[0:2])
            exchange: str = decode_domain_name(self.response, self.rdata_offset + 2, self.domain_cache)[0]
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

        self.decode()

    def decode(self):
        """
        Decode response bytes

        The response has 5 sections (just like the request):
        1. Header
        2. Question
        3. Answer
        4. Authority  (we will ignore this for now)
        5. Additional

        The header is formatted similarly to the request header.
        The question is formatted similarly to the request question (it might also be the same as the request question).
        The answer section contains resource records.
        The authority section contains resource records, but we will ignore it for now.
        The additional section contains resource records.
        """

        # Parse header
        self.id = decode_int(self.response_bytes[0:2])
        self.flags = decode_int(self.response_bytes[2:4])
        self.authoritative = bool(self.flags & 0x0400)
        self.rcode = self.flags & 0x000F
        self.question_count = decode_int(self.response_bytes[4:6])
        self.answer_count = decode_int(self.response_bytes[6:8])
        self.additional_count = decode_int(self.response_bytes[10:12])

        offset: int = HEADER_SIZE
        domain_name_cache: Dict[int, str] = {}  # Cache of domain names at offset to avoid parsing them multiple times
        qname, offset = decode_domain_name(self.response_bytes, offset, domain_name_cache)

        offset += 4  # Skip QTYPE and QCLASS for question section

        # Parse records in answer section and additional section (skip authority section)
        for _ in range(self.answer_count):
            record: Record = Record(self.response_bytes, offset, domain_name_cache, self.authoritative)
            self.answer_records.append(record)
            offset = record.end_index

        for _ in range(self.additional_count):
            record: Record = Record(self.response_bytes, offset, domain_name_cache, self.authoritative)
            self.additional_records.append(record)

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
            print("NOTFOUND")  # TODO: throw error instead?

    def validate(self):
        if self.rcode == 1:  # Return code
            raise FormatError
        elif self.rcode == 2:
            raise ServerFailure
        elif self.rcode == 4:
            raise NotImplement
        elif self.rcode == 5:
            raise Refused

