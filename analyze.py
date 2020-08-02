import struct
import socket
import pcapy
import sys

def ethernetAddress(addr):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])

def parse_ethernet(eth_header):
    header = struct.unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(header[2])
    dstmac = ethernetAddress(packet[0:6])
    srcmac= ethernetAddress(packet[6:12])
    return [eth_protocol,dstmac,srcmac]

def parse_ip(ipheader):
    header = struct.unpack('!BBHHHBBH4s4s', ipheader)
    temp_ipHeader_length = header[0]
    iphHeaderLength = (temp_ipHeader_length & 0xF) * 4
    transport_layer_protocol = header[6]
    srcip = socket.inet_ntoa(header[8])
    dstip = socket.inet_ntoa(header[9])
    return [transport_layer_protocol,iphHeaderLength,srcip,dstip]

def tcp_parse(tcp_header):
    header = struct.unpack('!HHLLBBHHH', tcp_header)
    source_port = header[0]
    dest_port = header[1]
    doff_reserved = header[4]
    tcph_length = (doff_reserved >> 4)*4
    return [tcph_length,source_port,dest_port]

def udp_parse(udp_header):
    header = struct.unpack('!HHHH', udp_header)
    source_port = header[0]
    dest_port = header[1]
    return [source_port,dest_port]

def parse_packet(packet):
    # Ethernet propocol
    ethernet_length = 14
    eth_header = packet[:14]
    eth_protocol = parse_ethernet(eth_header)[0]
    dstmac = parse_ethernet(eth_header)[1]
    srcmac = parse_ethernet(eth_header)[2]

    # IP protocal
    if eth_protocol == 8:
        ip_header = packet[ethernet_length : ethernet_length+20]
        transportLayer_protocol = parse_ip(ip_header)[0]
        iph_length = parse_ip(ip_header)[1]
        srcip = parse_ip(ip_header)[2]
        dstip = parse_ip(ip_header)[3]

        # TCP protocol
        if transportLayer_protocol == 6:
            tcp_start = iph_length + ethernet_length
            tcp_header = packet[tcp_start : tcp_start+20]

            tcp_Length = tcp_parse(tcp_header)[0]
            tcpSrcport = tcp_parse(tcp_header)[1]
            tcpDstport = tcp_parse(tcp_header)[2]

            http_start = ethernet_length+iph_length+tcp_Length
            http_content = packet[http_start:]

            # HTTP protocol
            if str(http_content).find("Connection") != -1:
                global successHttp
                successHttp += 1
                if str(tcpSrcport) == "80":
                    res = str(http_content).split(' ')
                    http_status = str(res[1])
                else:
                    res = str(http_content).split(' ')
                    http_status = str(res[0])[2:].lower()

                print("http ",http_status," tcp  srcmac:",srcmac)
                print("srcip:",srcip," srcport:",tcpSrcport)
                print("dstmac:",dstmac," dstip:",dstip)
                print("dstport:",tcpDstport)
            else:
                return


        # UDP packets
        elif transportLayer_protocol == 17:
            global successDNS
            successDNS += 1
            udp_start = iph_length + ethernet_length
            udph_length = 8
            udp_header = packet[udp_start : udp_start+8]
            udpSrcport = udp_parse(udp_header)[0]
            udpDstport = udp_parse(udp_header)[1]

            h_size = ethernet_length + iph_length + udph_length
            dns_content = packet[h_size:]

            id, check, qdcount, ancount, nscount, arcount = struct.Struct("!6H").unpack_from(dns_content)
            qr = check & 0x8000
            if qr != 0:
                dns_status = "response"
            else:
                dns_status = "query"

            print("dns ",dns_status," udp  srcmac:",srcmac)
            print("srcip:",srcip," srcport:",udpSrcport)
            print("dstmac:",dstmac," dstip:",dstip," dstport:",udpDstport)




if __name__ == "__main__":
    # list all devices
    dev = pcapy.findalldevs()
    # set network interface to promiscuous mode
    promiscuous = 1
    cap = pcapy.open_live(dev[0], 65536, promiscuous, 5000)

    # traffic filter
    checkOtherProtocol = True
    flag = sys.argv[1]
    if flag == "http":
        cap.setfilter('tcp port 80')
    elif flag == "dns":
        cap.setfilter('udp port 53')
    else:
        print("Wrong input, please input either http or dns.")
        checkOtherProtocol = False

    successHttp,successDNS = 0,0
    while True and checkOtherProtocol:
        # capture next packet
        (header, packet) = cap.next()
        parse_packet(packet)
        if successHttp > 3 or successDNS > 3:
            sys.exit()


