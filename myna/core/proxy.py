# coding:utf-8
import socket
import thread
import select
import elg

BUFLEN = 8192
HTTPVER = 'HTTP/1.1'
VERSION = "0.1"


class BaseSampler(object):
    host = "0.0.0.0"
    logger = elg.EasyLogging.get_logger(to_console=True)

    def __init__(self, method, path, protocol, raw_request, raw_response):
        self.method = method
        self.path = path
        self.protocol = protocol
        self.raw_request = raw_request
        self.raw_response = raw_response
        sample_it = self.host and path.find(self.host) != -1
        print path
        if self.host == "0.0.0.0" or sample_it:
            self.process()

    def to_file(self, buffer):
        with open("temp.txt", "w") as f:
            f.write(buffer)

    def process(self):
        print self.method, self.path, self.protocol, \
            "Request lenght: %d, Response lenght : %d" % \
            (len(self.raw_request), len(self.raw_response))


class RequestForwardingHandler:
    timeout = 60
    client_socket = target_socket = None

    def __init__(self, connection, address, sampler=None):
        self.client_socket = connection
        self.client_addr, self.client_port = address
        self.request_buffer = self.response_buffer = b''
        try:
            self.method, self.path, self.protocol = self.read_base_header()  # read head to buffer
            print "accepted request:", self.method, self.path, self.protocol
            self.process()
            self.client_socket.close()
            self.target_socket.close()
            if sampler:
                sampler(self.method, self.path, self.protocol, self.request_buffer, self.response_buffer)
        except Exception, e:
            print "Handler request error:", e

    def process(self):
        if self.method.upper() == 'CONNECT':
            self.process_connect()
        elif self.method.upper() in ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT',
                                     'DELETE', 'TRACE'):
            self.process_http_method()

    def read_base_header(self):
        while 1:
            self.request_buffer += self.client_socket.recv(BUFLEN)
            end = self.request_buffer.find('\n')
            if end != -1:
                break
        request_head = self.request_buffer[:end + 1]
        return request_head.split()

    def process_connect(self):
        self.content_target(self.path)
        self.client_socket.send(HTTPVER + ' 200 Connection established\n' +
                                'Proxy-agent: %s\n\n' % VERSION)
        self.request_buffer = b''
        self.sock_forwarding()

    def process_http_method(self):
        self.path = self.path[7:]
        i = self.path.find('/')
        host = self.path[:i]
        path = self.path[i:]
        self.content_target(host)
        self.target_socket.send(self.request_buffer)
        self.sock_forwarding()  # finish forwarding

    def content_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i + 1:])
            host = host[:i]
        else:
            port = 80
        soc_family, _, _, _, address = socket.getaddrinfo(host, port)[0]
        self.target_socket = socket.socket(soc_family)
        self.target_socket.connect(address)

    def sock_forwarding(self):
        socs = [self.client_socket, self.target_socket]
        for _ in xrange(self.timeout):
            recv, _, error = select.select(socs, [], socs, 1.0)
            if error:
                break
            if recv:
                for in_ in recv:
                    data = in_.recv(BUFLEN)
                    if in_ is self.client_socket:
                        self.request_buffer += data
                        out = self.target_socket
                    else:
                        out = self.client_socket
                        self.response_buffer += data
                    if data:
                        out.send(data)
                        count = 0


def start_server(host='0.0.0.0', port=12344, IPv6=False,
                 handler=RequestForwardingHandler, sampler=BaseSampler, callback=None):
    socket_type = socket.AF_INET6 if IPv6 is True else socket.AF_INET
    server_socket = socket.socket(socket_type)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))

    print "Listen on %s:%d." % (host, port)
    server_socket.listen(5)
    ths = []
    try:
        while 1:
            readable, writable, __ = select.select([server_socket], [], [], 1.)
            for s in readable:
                if s is server_socket:
                    ths.append(thread.start_new_thread(handler,server_socket.accept(),dict(sampler=sampler)))
    except KeyboardInterrupt:
        print "Stopping now ..."
    finally:
        server_socket.close()
        print "Server closed."
        if callback:
            callback()


if __name__ == '__main__':
    start_server()
