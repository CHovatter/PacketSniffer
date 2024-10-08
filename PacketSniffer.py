import socket
import struct
import textwrap
import keyboard

class HaltException(Exception): pass


# currently only compatible with Windows devices with python, unless using .exe

# for output formatting.
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t -'
TAB_4 = '\t\t\t\t - '
DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '




def sniff():
    try:
        print(TAB_1 + 'Individual packets are separated by "----------"')
        input(TAB_1 + 'Press enter to begin, hold h to halt:')
        # initialize socket objects host and conn
        host = socket.gethostbyname(socket.gethostname())
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

        # create a raw socket and bind it to the public interface
        conn.bind((host, 0))
        # include IP headers
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # receives all packets
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        while True:
            raw_data, addr = conn.recvfrom(65536)
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(raw_data)
            print(DATA_TAB_1 + "\n"'----------')
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            print(TAB_2 + 'Data:')
            print(format_multi_line(DATA_TAB_3, data))

            if keyboard.is_pressed('h'):
                raise HaltException("halted, press enter to exit")
                

            # ICMP
            elif proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))


            # TCP
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}. Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}. PSH: {}, RST: {}, SYN: {}, FIN: {}'. format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))


            # UDP
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))
            print("\n")
            
    except HaltException as halt:
        print(halt)
        input()

# Unpacks IPv4 Packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


# Returns formatted IPv4 address  Ex: 192.168.0.1
def ipv4(addr):
    return ".".join(map(str, addr))


# Unpacks UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# Unpacks ICMP Packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


# Unpacks TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# Formats multi-line data
def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


sniff()
