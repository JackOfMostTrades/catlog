from dnslib import RR, QTYPE, RCODE
from dnslib.server import DNSServer, BaseResolver


class CatlogResolver(BaseResolver):
    def __init__(self):
        self.txtMap = {}
        self.udp_server = None

    def setTxt(self, domain, value):
        self.txtMap[domain.lower()] = value

    def clearTxt(self, domain):
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
            reply.add_answer(*RR.fromZone('{} IN TXT {}'.format(qname, self.txtMap[qname])))
        else:
            reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def start(self):
        self.udp_server = DNSServer(self, port=1153)
        self.udp_server.start_thread()

    def stop(self):
        self.udp_server.stop()
