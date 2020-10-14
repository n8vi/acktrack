#!/usr/bin/env python3

from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import code
import socket
import re
# import pytest

class DebugSession():
    def __init__(self, progname):
        self.gdbmi = GdbController()

        resp = self.cmd('-file-exec-and-symbols '+progname)
        assert "done" in [r['message'] for r in resp]

        resp = self.cmd('-break-insert main')
        assert "done" in [r['message'] for r in resp]

        resp = self.cmd('-exec-run')
        assert "running" in [r['message'] for r in resp]

        print("initialized")

    def cmd(self,cmd):
        ret = self.gdbmi.write(cmd)
        return ret

    def call_func(self,funcstr):

        funcstr = funcstr.replace('"', '\\"')

        resp = self.cmd(f'-data-evaluate-expression "{funcstr}"')

        try:
            if "error" in [r['message'] for r in resp]:
                resp = self.cmd(f'-data-evaluate-expression "(void*){funcstr}"')
        except:
            pass

        result = [item['payload'] for item in resp if item['type'] == 'result']
        ret = result[0]['value']

        if '"' in ret:
            return '"'+ret.split('"')[1]+'"'
        else:
            return ret.split(' ')[0]


        return ret


def test_get_port():
    d = DebugSession('fixture')
    sa = d.call_func('parseendpoint("127.0.0.1:80")')
    port = socket.ntohs(int(d.call_func(f'get_port({sa})')))
    assert port == 80
    sa = d.call_func('parseendpoint("0.0.0.0:0")')
    port = socket.ntohs(int(d.call_func(f'get_port({sa})')))
    assert port == 0
    sa = d.call_func('parseendpoint("255.255.255.255:65535")')
    port = socket.ntohs(int(d.call_func(f'get_port({sa})')))
    assert port == 65535
    sa = d.call_func('parseendpoint("[::1]:80")')
    port = socket.ntohs(int(d.call_func(f'get_port({sa})')))
    assert port == 80
    sa = d.call_func('parseendpoint("[::]:0")')
    port = socket.ntohs(int(d.call_func(f'get_port({sa})')))
    assert port == 0
    sa = d.call_func('parseendpoint("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")')
    port = socket.ntohs(int(d.call_func(f'get_port({sa})')))
    assert port == 65535

def test_get_ip_str():
    d = DebugSession('fixture')
    sa = d.call_func('parseendpoint("127.0.0.1:80")')
    ipstr = d.call_func(f'get_ip_str({sa})')
    assert ipstr == '"127.0.0.1"'
    sa = d.call_func('parseendpoint("0.0.0.0:0")')
    ipstr = d.call_func(f'get_ip_str({sa})')
    assert ipstr == '"0.0.0.0"'
    sa = d.call_func('parseendpoint("255.255.255.255:65535")')
    ipstr = d.call_func(f'get_ip_str({sa})')
    assert ipstr == '"255.255.255.255"'
    sa = d.call_func('parseendpoint("[::1]:80")')
    ipstr = d.call_func(f'get_ip_str({sa})')
    assert ipstr == '"::1"'
    sa = d.call_func('parseendpoint("[::]:0")')
    ipstr = d.call_func(f'get_ip_str({sa})')
    assert ipstr == '"::"'
    sa = d.call_func('parseendpoint("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")')
    ipstr = d.call_func(f'get_ip_str({sa})')
    assert ipstr == '"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"'

def test_get_family():
    d = DebugSession('fixture')
    sa = d.call_func('parseendpoint("127.0.0.1:80")')
    fam = d.call_func(f'get_family({sa})')
    assert fam == '"ipv4"'
    sa = d.call_func('parseendpoint("0.0.0.0:0")')
    fam = d.call_func(f'get_family({sa})')
    assert fam == '"ipv4"'
    sa = d.call_func('parseendpoint("255.255.255.255:65535")')
    fam = d.call_func(f'get_family({sa})')
    assert fam == '"ipv4"'
    sa = d.call_func('parseendpoint("[::1]:80")')
    fam = d.call_func(f'get_family({sa})')
    assert fam == '"ipv6"'
    sa = d.call_func('parseendpoint("[::]:0")')
    fam = d.call_func(f'get_family({sa})')
    assert fam == '"ipv6"'
    sa = d.call_func('parseendpoint("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535")')
    fam = d.call_func(f'get_family({sa})')
    assert fam == '"ipv6"'

def get_endpointstring(ip, port):
    if ':' in ip:
        return f"[{ip}]:{port}"
    else:
        return f"{ip}:{port}"

def check_filter(d, lip, lport, rip, rport):
    a = d.call_func('acktrack_alloc()')
    leps = get_endpointstring(lip, lport)
    lsa = d.call_func(f'parseendpoint("{leps}")')
    d.call_func(f'set_local({a}, {lsa})');
    reps = get_endpointstring(rip, rport)
    rsa = d.call_func(f'parseendpoint("{reps}")')
    d.call_func(f'set_remote({a}, {rsa})');
    f = d.call_func(f'get_filter({a})')
    assert f == f'"tcp and ((src host {lip} and src port {lport} and dst host {rip} and dst port {rport}) or (src host {rip} and src port {rport} and dst host {lip} and dst port {lport}))"'

def test_get_filter():
    d = DebugSession('fixture')
    check_filter(d, "10.10.10.10", "12345", "200.200.200.200", "200")
    check_filter(d, "2002::ffff", "12345", "2600::1234", "200")

def test_relseq_rseq():
    d = DebugSession('fixture')
    a = d.call_func('acktrack_alloc()');
    d.call_func(f"set_rseqorig({a}, 1000)")
    b = d.call_func(f'relseq({a}, 1024, 0)')
    assert b == '24', "remote relative sequence number calculation incorrect"

def test_relseq_lseq():
    d = DebugSession('fixture')
    a = d.call_func('acktrack_alloc()');
    d.call_func(f"set_lseqorig({a}, 1000)")
    b = d.call_func(f'relseq({a}, 1024, 1)')
    assert b == '24', "local relative sequence number calculation incorrect"

def test_acktrack_t():
    d = DebugSession('fixture')
    a = d.call_func('acktrack_alloc()');
    d.call_func(f"set_lastrseq({a}, 1000)")
    d.call_func(f"set_lastlseq({a}, 2000)")
    d.call_func(f"set_lastrack({a}, 3000)")
    d.call_func(f"set_lastlack({a}, 4000)")
    b = d.call_func(f'acktrack_lastrseq({a})')
    assert b == '1000', "lastrseq() failed"
    b = d.call_func(f'acktrack_lastlseq({a})')
    assert b == '2000', "lastlseq() failed"
    b = d.call_func(f'acktrack_lastrack({a})')
    assert b == '3000', "lastrack() failed"
    b = d.call_func(f'acktrack_lastlack({a})')
    assert b == '4000', "lastlack() failed"
    d.call_func(f"set_lastrseq({a}, 4000)")
    d.call_func(f"set_lastlseq({a}, 3000)")
    d.call_func(f"set_lastrack({a}, 2000)")
    d.call_func(f"set_lastlack({a}, 1000)")
    b = d.call_func(f'acktrack_lastrseq({a})')
    assert b == '4000', "lastrseq() failed"
    b = d.call_func(f'acktrack_lastlseq({a})')
    assert b == '3000', "lastlseq() failed"
    b = d.call_func(f'acktrack_lastrack({a})')
    assert b == '2000', "lastrack() failed"
    b = d.call_func(f'acktrack_lastlack({a})')
    assert b == '1000', "lastlack() failed"

def test_socket_filter():
    d = DebugSession('fixture')
    s = d.call_func('sck_conn("8.8.8.8:53")')
    assert s != '-1', 'failed to create socket (invalid test result)'
    a = d.call_func(f'acktrack_create({s})')
    assert a != '0x0', 'failed to create acktrack_t object'
    f = d.call_func(f"get_filter({a})")
    assert re.search(r'^"tcp and \(\(src host ([0-9.]+) and src port ([0-9]+) and dst host 8.8.8.8 and dst port 53\) or \(src host 8.8.8.8 and src port 53 and dst host \1 and dst port \2\)\)"$', f), 'failed to generate accurate filter string'

