import argparse
import dns_data as dns
import socket
import timeit as timer

from DnsError import FormatError, ServerFailure, NotImplement, Refused


def request_ip(dns_args: argparse.Namespace):
    """Request IP address from DNS server"""

    timeout: int = dns_args.t
    max_retries: int = dns_args.r
    port: int = dns_args.p
    server_ip: str = dns_args.server
    domain_name: str = dns_args.name

    if server_ip[0] == "@":  # @server -> server
        server_ip = server_ip[1:]

    query_type: dns.QueryType = dns.QueryType.A
    if dns_args.mx:
        query_type = dns.QueryType.MX
    elif dns_args.ns:
        query_type = dns.QueryType.NS

    print(f"DnsClient sending request for {domain_name}")
    print(f"Server: {server_ip}")
    print(f"Request type: {query_type.name}\n")

    retries: int = 0

    while retries < max_retries:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:  # Open a UDP socket
                sock.settimeout(timeout)

                # Create a DNS request
                request: dns.Request = dns.Request(domain_name, query_type)

                # Send the request to the server and wait for the response
                request_bytes: bytes = request.to_bytes()

                start_time: float = timer.default_timer()

                sock.sendto(request_bytes, (server_ip, port))
                response_bytes = sock.recv(1024)  # 1024 bytes as the max size of a DNS response

                time: float = timer.default_timer() - start_time

            print(f"Response received after {time:.3f} seconds ({retries} retries)")
            response: dns.Response = dns.Response(response_bytes)

            "Will throw the appropriate errors"
            response.validate()

            response.print()
            break

        except socket.timeout as timeout_error:
            print(f"ERROR\tTimeout while contacting server: {timeout_error}. Retransmitting request.")
            retries += 1
            continue
        except socket.gaierror as gai_error:
            print(f"ERROR\tSocket error: {gai_error}")
            break
        except socket.herror as h_error:
            print(f"ERROR\tSocket error: {h_error}")
            break
        except socket.error as socket_error:
            print(f"ERROR\tSocket error: {socket_error}")
            break
        except FormatError:
            print("FORMAT ERROR")
            continue
        except ServerFailure:
            print("SERVER FAILURE")
            continue
        except NotImplement:
            print("NOT IMPLEMENTED")
            continue
        except Refused:
            print("REFUSED")
            continue


    if retries == max_retries:
        print(f"ERROR\tMaximum retries exceeded: {max_retries}")


if __name__ == '__main__':
    """
    Parse arguments for DNS client
    
    Usage: 
    python DnsClient.py [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description='DNS Client')
    parser.add_argument('-t', metavar='timeout', help="How long to wait in seconds before retransmitting an "
                                                      "unanswered query", type=int, default=5)
    parser.add_argument('-r', metavar='max-retries', help="Maximum number of times to retransmit an "
                                                          "unanswered query", type=int, default=3)
    parser.add_argument('-p', metavar='port', help="UDP Port number of the DNS server", type=int, default=53)

    group = parser.add_mutually_exclusive_group(required=False)  # [-mx | -ns]
    group.add_argument('-mx', help="Mail server", action='store_true')
    group.add_argument('-ns', help="Name server", action='store_true')

    parser.add_argument('server', metavar='@server', help="IPv4 address of the DNS server, in a.b.c.d.format")
    parser.add_argument('name', help="Domain name to query for")

    args: argparse.Namespace = parser.parse_args()
    request_ip(args)

