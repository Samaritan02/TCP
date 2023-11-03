"""
这是等待你完成的代码。正常情况下，本文件是你唯一需要改动的文件。
你可以任意地改动此文件，改动的范围当然不限于已有的五个函数里。（只要已有函数的签名别改，要是签名改了main里面就调用不到了）
在开始写代码之前，请先仔细阅读此文件和api文件。这个文件里的五个函数是等你去完成的，而api里的函数是供你调用的。
提示：TCP是有状态的协议，因此你大概率，会需要一个什么样的数据结构来记录和维护所有连接的状态
"""

# 本实验部分代码由https://github.com/features/copilot 给出
from api import *
from scapy.all import *
from collections import deque
import time

## 生成TCP四元组（python语言中tuple可以被hash）
def ConnID(identifier: ConnectionIdentifier):
    return (identifier['src']['ip'], identifier['src']['port'], identifier['dst']['ip'], identifier['dst']['port'])

# 框架生成自copilot（链接见代码开始处），根据wireshark抓包结果做了修正 
def parse_TCP_header(data: bytes):
    seq = int.from_bytes(data[4:8], byteorder='big')
    ack = int.from_bytes(data[8:12], byteorder='big')
    header_len = (data[12] >> 4) * 4
    clean_data = data[header_len:]

    if data[13] & 0x01:
        flags = 'FA'
    elif (data[13] >> 1) & 0x01:
        flags = 'SA'
    elif (data[13] >> 2) & 0x01:
        flags = 'RA'
    else:
        flags = 'simpleACK'
    
    return seq, ack, flags, clean_data

# init()框架生成自copilot，根据实际需要添加TCP四元组信息以提升代码整洁度
# 关于实现一个TCP连接的类，与郑懿（2020012859），孙一川（2020012860）讨论过实现的框架
class TCP_Conn:
    def __init__(self, conn) -> None:
        self.send_buffer = deque(maxlen=20)  # 发送缓冲 [clean_data, seq, flags]（其中clean_data指去除报头的数据，便于超时重发时的数据）
        self.time_stamp = 0                  # 记录时间戳
        self.conn = conn                     # 连接对象
        self.state = 'CLOSED'                # 连接状态
        self.next_send = 0                   # 下一个发送的可用序号
        self.send_base = 0                   # 发送窗口的起始序号
        self.recv_base = 0                   # 下一个接收的可用序号

        self.dst_ip = conn['dst']['ip']      # 目的ip
        self.dst_port = conn['dst']['port']  # 目的端口
        self.src_ip = conn['src']['ip']      # 源ip
        self.src_port = conn['src']['port']  # 源端口

    # 发送SYN报文，并将其放入缓冲区以备重传
    # 所有发送报文的框架均由copilot生成，部分细节根据wireshark抓包结果及课上所学知识进行修正，之后类似发送报文处不再一一注明
    def app_connect(self):
        SYN = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='S', seq=0))[TCP])
        self.send_buffer.append([b'', 0, 'S']) # 注意到对于SYN报文来说，其序列号总可以任意指定，因此恒指定为0，将其放入缓冲区    
        tcp_tx(self.conn, SYN)

        # 维护状态
        self.next_send += 1
        self.state = 'SYN_SENT'
        self.time_stamp = time.time() # 开一个计时器，以确保实现超时重传

    # 发送含有数据的报文，并将其放入缓冲区以备重传
    def app_send(self, data: bytes):
        DATA = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.recv_base) / data)[TCP])
        tcp_tx(self.conn, DATA)

        if self.send_buffer.__len__() == 0: # 如果发送缓存为空，则开一个计时器，以确保实现超时重传
            self.time_stamp = time.time()   
        self.send_buffer.append([data, self.next_send, 'A']) # 将data放入缓冲区，以备超时重传
        self.next_send += len(data) # 此时下一个即将要发的序列号应根据数据大小向后移动

    # 发送FIN报文，并将其放入缓冲区以备重传
    def app_fin(self):
        FIN = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='FA', seq=self.next_send, ack=self.recv_base))[TCP])
        tcp_tx(self.conn, FIN)

        self.send_buffer.append([b'', self.next_send, 'FA']) # 将FIN报文放入缓冲区，以确保实现超时重传
        self.next_send += 1
        self.state = 'FIN_WAIT_1' # 对于客户端来说，第一次挥手后，状态会改为FIN WAIT 1

    # 发送RST报文，由于此时直接关闭连接，因此直接将状态置为CLOSED
    def app_rst(self):
        RST = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='RA', seq=self.next_send, ack=self.recv_base))[TCP])
        tcp_tx(self.conn, RST)

        self.state = 'CLOSED'

    # 有限状态转移机的处理方式与如下同学讨论过：郑懿（2020012859），孙一川（2020012860），并进行了代码的review工作
    def tcp_rx(self, data: bytes):
        data_seq, data_ack, data_flags, clean_data = parse_TCP_header(data)         # 获取当前收到的数据TCP报头的一些状态信息以及去除报头的数据（即clean_data）
        # 如果收到了RST报头，直接关闭连接并通知应用层
        if data_flags == 'RA':
            if data_seq == self.recv_base:
                self.state = 'CLOSED'
                app_peer_rst(self.conn)
            return
        
        else:
            # 首先处理SYNACK情况，此时必须同时满足状态为SYN SENT 和 收到报文为SYNACK两个条件
            if self.state == 'SYN_SENT' and data_flags == 'SA':
                # 检验SYNACK报文的ACK是否与我们将要发送的下一个序列号相同，以保证收到正确SYNACK
                if data_ack == self.next_send:
                    ACK = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=data_ack, ack=data_seq+1))[TCP])
                    tcp_tx(self.conn, ACK)
                    app_connected(self.conn) # 通知应用层

                    self.state = 'ESTABLISHED' # 第三次握手后，需要将状态改为ESTABLISHED
                    self.recv_base = data_seq + 1 # 根据服务器端发送的序列号维护下次报文发送的ACK号，以实现状态同步
                    self.send_buffer.popleft() # 弹出缓存的SYN报文
                    self.time_stamp = time.time() # 重启定时器
                    return
                else:
                    return
            
            else:
                # 首先处理ACK报文和含有数据的报文
                if self.send_base <= data_ack and data_ack <= self.next_send: # 检查发来的ACK号所对应的数据是否在缓存区内
                    while self.send_buffer.__len__() != 0 and self.send_buffer[0][1] < data_ack:
                        self.send_buffer.popleft() # 弹出所有被累计确认的报文
                    
                    self.send_base = data_ack # 更新send_base，即发送缓存区第一个（如果有）数据的seq
                    self.time_stamp = time.time() # 重启定时器
                else:
                    pass
                
                if len(clean_data) != 0: # 如果这是一个有数据的报文
                    if data_seq == self.recv_base: # 检查收到数据的seq是否和期望接收的seq相匹配，不匹配则丢掉（即不实现接受缓存）
                        app_recv(self.conn, clean_data) # 只有匹配的数据才会上交应用层
                        ACK = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.recv_base + len(clean_data)))[TCP])
                        tcp_tx(self.conn, ACK) # 回发累计确认ACK

                        self.recv_base += len(clean_data) # 更新下一个期望接收的seq
                        return
                    else:
                        ACK = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.recv_base))[TCP])
                        tcp_tx(self.conn, ACK) # 回发累计确认ACK
                        return
                else:
                    pass
                
                # 接下来处理FIN报文
                if data_flags == 'FA':
                    if data_seq == self.recv_base: # 如果收到的序列号和期待的序列号相等，则回送ACK
                        ACK = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.recv_base+1))[TCP])
                        tcp_tx(self.conn, ACK)

                        self.recv_base += 1
                    else:
                        ACK = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.recv_base))[TCP])
                        tcp_tx(self.conn, ACK)

                        return
                    
                    if self.state == 'ESTABLISHED': # 如果目前状态是ESTABLISHED，则进入CLOSE WAIT状态，并通知应用层
                        ACK = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.recv_base))[TCP])
                        tcp_tx(self.conn, ACK)

                        self.state = 'CLOSE_WAIT'
                        app_peer_fin(self.conn)# 通知应用层对端发起半关闭连接
                        return

                    elif self.state == 'FIN_WAIT_1': # 如果目前状态是FIN WAIT 1，则进入CLOSING状态
                        ACK = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.recv_base))[TCP])
                        tcp_tx(self.conn, ACK)

                        self.state = 'CLOSING'
                        return

                    elif self.state == 'FIN_WAIT_2': # 如果目前状态是FIN WAIT 2，则进入TIME WAIT状态
                        ACK = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.next_send, ack=self.recv_base))[TCP])
                        tcp_tx(self.conn, ACK)

                        self.state = 'TIME_WAIT'
                        # time.sleep(30) # 此时应该等待30s，为方便测试将这一句注释
                        release_connection(self.conn) # 通知应用层释放连接
                        return
                    
                    else:
                        return
                        
                # 由于已经处理了ACK 和 数据，之后仅需处理状态转移  
                else:
                    if data_seq == self.recv_base:
                        if self.state == 'FIN_WAIT_1': # 如果在FIN WAIT 1状态下收到ACK，并且所有数据已经被ACK，此时需进入FIN WAIT 2状态
                            if self.send_buffer.__len__() == 0:
                                self.state = 'FIN_WAIT_2'
                                return
                        
                        elif self.state == 'LAST_ACK': # 如果是在LAST ACK状态下收到ACK，则直接关闭连接即可
                            self.state = 'CLOSED'
                            release_connection(self.conn)
                            return
                        
                    else:
                        return
        
                        
    # 实现超时重传功能，即如果超过给定时间，且发送缓存非空，则重新发送发送缓存中的第一个报文              
    def tick(self):
        if time.time() - self.time_stamp > 1:
            if len(self.send_buffer) != 0:
                send_base_data, send_base_seq, send_base_flags = self.send_buffer[0]  
                resend_data = bytes((IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.src_port, dport=self.dst_port,
                                        flags=send_base_flags, seq=send_base_seq, ack=self.recv_base) / send_base_data)[TCP])
                tcp_tx(self.conn, resend_data)

                self.time_stamp = time.time() 
            else:
                pass
        else:
            pass

# --------------------------------------------------以下是供main函数调用的函数--------------------------------------------------


tcp_list = {}  # 连接列表，key为每个连接的四元组，value为每个连接实例化的TCP_Conn对象。关于存储的方式，和郑懿（2020012859）讨论过

# 接下来的每一个函数，实际上只是调用了TCP_Conn实例化对象中的相应函数，不再一一说明
# 由于该部分代码重复性强，基本都是copilot生成的，部分地方根据情况修改了细节

def app_connect(conn: ConnectionIdentifier):
    """
    当有应用想要发起一个新的连接时，会调用此函数。想要连接的对象在conn里提供了。
    你应该向想要连接的对象发送SYN报文，执行三次握手的逻辑。
    当连接建立好后，你需要调用app_connected函数，通知应用层连接已经被建立好了。
    :param conn: 连接对象
    :return: 
    """
    connection = TCP_Conn(conn) # 实例化TCP连接对象
    tcp_list[ConnID(conn)] = connection
    connection.app_connect()
    print("app_connect", conn)


def app_send(conn: ConnectionIdentifier, data: bytes):
    """
    当应用层想要在一个已经建立好的连接上发送数据时，会调用此函数。
    :param conn: 连接对象
    :param data: 数据内容，是字节数组
    :return:
    """
    connection = tcp_list[ConnID(conn)]
    connection.app_send(data)
    print("app_send", conn, data.decode(errors='replace'))


def app_fin(conn: ConnectionIdentifier):
    """
    当应用层想要半关闭连接(FIN)时，会调用此函数。
    :param conn: 连接对象
    :return: 
    """
    connection = tcp_list[ConnID(conn)]
    connection.app_fin()
    print("app_fin", conn)


def app_rst(conn: ConnectionIdentifier):
    """
    当应用层想要重置连接(RES)时，会调用此函数
    :param conn: 连接对象
    :return: 
    """
    connection = tcp_list[ConnID(conn)]
    connection.app_rst()
    print("app_rst", conn)


def tcp_rx(conn: ConnectionIdentifier, data: bytes):
    """
    当收到TCP报文时，会调用此函数。
    正常情况下，你会对TCP报文，根据报文内容和连接的当前状态加以处理，然后调用0个~多个api文件中的函数
    :param conn: 连接对象
    :param data: TCP报文内容，是字节数组。（含TCP报头，不含IP报头）
    :return: 
    """
    connection = tcp_list[ConnID(conn)]
    connection.tcp_rx(data)
    print("tcp_rx", conn, data.decode(errors='replace'))

# 每次调用tick函数，都遍历所有实例化的TCP_Conn对象，并实现超时重传（类似于多线程）
def tick():
    """
    这个函数会每至少100ms调用一次，以保证控制权可以定期的回到你实现的函数中，而不是一直阻塞在main文件里面。
    它可以被用来在不开启多线程的情况下实现超时重传等功能，详见主仓库的README.md
    """
    for connection in tcp_list.values():
        connection.tick()


