#!/usr/bin/env python3

from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import code
import socket
# import pytest

def call_func(funcstr):
    gdbmi = GdbController()

    response = gdbmi.write('-file-exec-and-symbols fixture')
    assert([item['message'] for item in response if item['type'] == 'result'][0] == 'done')

    response = gdbmi.write('-break-insert main')
    assert([item['message'] for item in response if item['type'] == 'result'][0] == 'done')

    response = gdbmi.write('-exec-run')
    assert([item['message'] for item in response if item['type'] == 'result'][0] == 'running')

    response = gdbmi.write('-data-evaluate-expression '+funcstr)
    result = [item['payload'] for item in response if item['type'] == 'result']
    ret = result[0]['value']
    if '"' in ret:
        return ret.split('"')[1]
    else:
        return int(result[0]['value'])

def test_get_port_v4():
    port = socket.ntohs(call_func('get_port(parseendpoint("127.0.0.1:80"))'))
    assert port == 80, "port number not preserved in calling get_port() on parseendpoint() result" 

def test_get_port_v6():
    port = socket.ntohs(call_func('get_port(parseendpoint("[::1]:80"))'))
    assert port == 80, "port number not preserved in calling get_port() on parseendpoint() result" 

def test_get_ip_str_v4():
    ip_str = call_func('get_ip_str(parseendpoint("127.0.0.1:80"))')
    assert ip_str == '127.0.0.1', "IPv4 address not preserved in calling get_ip_str() on parseendpoint() result" 
    
def test_get_ip_str_v6():
    ip_str = call_func('get_ip_str(parseendpoint("[::1]:80"))')
    assert ip_str == '::1', "IPv6 address not preserved in calling get_ip_str() on parseendpoint() result" 

