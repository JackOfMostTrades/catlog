from dnslib import RR, QTYPE, RCODE
from dnslib.server import DNSServer, BaseResolver


class SilentLogger:
    def log_pass(self, *args):
        pass

    def log_prefix(self, handler):
        pass

    def log_recv(self, handler, data):
        pass

    def log_send(self, handler, data):
        pass

    def log_request(self, handler, request):
        pass

    def log_reply(self, handler, reply):
        pass

    def log_truncated(self, handler, reply):
        pass

    def log_error(self, handler, e):
        pass

    def log_data(self, dnsobj):
        pass

class CatlogResolver(BaseResolver):
    def __init__(self):
        self.txtMap = {}
        self.udp_server = None

    def setTxt(self, domain: str, value: str) -> None:
        self.txtMap[domain.lower()] = value

    def clearTxt(self, domain: str) -> None:
        del self.txtMap[domain.lower()]

    def resolve(self, request, handler):
        """
            Respond to DNS request - parameters are request packet & handler.
            Method is expected to return DNS response
        """
        reply = request.reply()
        qname = request.q.qname.idna()[:-1].lower()
        qtype = QTYPE[request.q.qtype]
        if qtype == 'TXT' and qname in self.txtMap:
            reply.add_answer(*RR.fromZone('{} IN TXT "{}"'.format(qname, self.txtMap[qname])))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def start(self):
        self.udp_server = DNSServer(self, port=53, logger=SilentLogger())
        self.udp_server.start_thread()

    def stop(self):
        self.udp_server.stop()
