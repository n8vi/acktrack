#!/usr/bin/env python3

from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import code
import socket
# import pytest

class DebugSession():
    def __init__(self, progname):
        self.gdbmi = GdbController()
        response = self.cmd('')
        pprint(response)

        response = self.cmd('-file-exec-and-symbols '+progname)
        #assert([item['message'] for item in response if item['type'] == 'result'][0] == 'done')
        # assert response['message'] == 'done'

        response = self.cmd('-break-insert main')
        # assert [item['message'] for item in response if item['type'] == 'result'][0] == 'done')
        # assert response['message'] == 'done'

        response = self.cmd('-exec-run')
        # assert([item['message'] for item in response if item['type'] == 'result'][0] == 'running')
        # assert response['message'] == 'running'
        # assert response['message'] == 'library-loaded'

        print("=-=-=-=-=-= session initialized")

    def cmd(self,cmd):
        print("====>", cmd)
        ret = self.gdbmi.write(cmd)
        print("<====", end="")
        pprint(ret)
        return ret

    def call_func(self,funcstr):

        resp = self.cmd('-data-evaluate-expression '+funcstr)

        try:
            if "'acktrack_alloc()' has unknown return type; cast the call to its declared return type" in [r['payload']['msg'] for r in response]:
                resp = self.cmd('-data-evaluate-expression (void*)'+funcstr)
        except:
            pass

        

        result = [item['payload'] for item in resp if item['type'] == 'result']
        ret = result[0]['value']

        return ret

#    if '"' in ret:
#        return ret.split('"')[1]
#    else:
#        return result[0]['value']

d = DebugSession('fixture')

code.interact(local=locals())

# a = d.call_func('acktrack_alloc()');

# d.call_func(f"set_lseqorig({a}, 1000)")
# 
# b = d.call_func(f'relseq({a}, 123')
# 
# print("relseq = ", b)

# code.interact(local=locals())




#def test_get_port_v4():
#    port = socket.ntohs(call_func('get_port(parseendpoint("127.0.0.1:80"))'))
#    assert port == 80, "port number not preserved in calling get_port() on parseendpoint() result" 
#
#def test_get_port_v6():
#    port = socket.ntohs(call_func('get_port(parseendpoint("[::1]:80"))'))
#    assert port == 80, "port number not preserved in calling get_port() on parseendpoint() result" 
#
#def test_get_ip_str_v4():
#    ip_str = call_func('get_ip_str(parseendpoint("127.0.0.1:80"))')
#    assert ip_str == '127.0.0.1', "IPv4 address not preserved in calling get_ip_str() on parseendpoint() result" 
#    
#def test_get_ip_str_v6():
#    ip_str = call_func('get_ip_str(parseendpoint("[::1]:80"))')
#    assert ip_str == '::1', "IPv6 address not preserved in calling get_ip_str() on parseendpoint() result" 

