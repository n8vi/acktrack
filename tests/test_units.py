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
            return ret


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

def test_get_port_v4():
    d = DebugSession('fixture')
    port = socket.ntohs(int(d.call_func('get_port(parseendpoint("127.0.0.1:80"))')))
    assert port == 80, "port number not preserved in calling get_port() on parseendpoint() result" 

def test_get_port_v6():
    d = DebugSession('fixture')
    port = socket.ntohs(int(d.call_func('get_port(parseendpoint("[::1]:80"))')))
    assert port == 80, "port number not preserved in calling get_port() on parseendpoint() result" 

def test_get_ip_str_v4():
    d = DebugSession('fixture')
    ip_str = d.call_func('get_ip_str(parseendpoint("127.0.0.1:80"))')
    assert ip_str == '"127.0.0.1"', "IPv4 address not preserved in calling get_ip_str() on parseendpoint() result" 
    
def test_get_ip_str_v6():
    d = DebugSession('fixture')
    ip_str = d.call_func('get_ip_str(parseendpoint("[::1]:80"))')
    assert ip_str == '"::1"', "IPv6 address not preserved in calling get_ip_str() on parseendpoint() result" 

