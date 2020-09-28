#!/usr/bin/env python3

from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import code
import socket
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

