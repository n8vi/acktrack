#!/usr/bin/env python3

from pytun import TunTapDevice
from time import sleep 

def calcchk(pkt):
    if len(pkt) % 2 == 1:
        pkt += [0]
    wpkt = [pkt[i]<<8|pkt[i+1] for i,x in enumerate(pkt) if not i%2]
    chk = sum(wpkt)
    print(1,"%x"%chk)
    chk = (chk & 0xffff) + (chk>>16)
    chk ^= 0xffff
    print(2,"%x"%chk)

    # wpkt = [0xffff ^ x for x in wpkt]
    # chk = sum(wpkt) & 0xffff
    # chk = 0xffff ^ chk
    # print("checksum %x"%chk)
    return chk


def parseecho(pkt):
    ident = pkt[0]<<8|pkt[1]
    seq = pkt[2]<<8|pkt[3]
    data = pkt[4:]
    # print(f"  ECHO: ident={ident} seq={seq}")
    # print( "    -> "+" ".join(["%.2x"%x for x in data]))

def parseicmp(pkt):
    typ = pkt[0]
    code = pkt[1]
    chk = pkt[2]<<8|pkt[3]
    # print(f"   type {typ} code {code} chk {chk} ")
    payload = pkt[4:]
    if typ == 8:
        parseecho(payload)
        pkt[0] = 0
        pkt[2] = 0
        pkt[3] = 0
        chk = calcchk(pkt)
        pkt[2] = chk>>8
        pkt[3] = chk&0xff
        return pkt

def parsetcp(pkt):
    pass

def parseudp(pkt):
    pass

def parse4(pkt):
    print( "     got "+" ".join(["%.2x"%x for x in pkt]))
    vihl = pkt[0]
    ver = vihl >> 4;
    ihl = (vihl & 0x0f)*4
    tos = pkt[1]
    tlen = pkt[2]<<8|pkt[3]
    ident = pkt[4]<<8|pkt[5]
    flags_fragofs = pkt[6]<<8|pkt[7]
    ttl = pkt[8]
    proto = pkt[9]
    chk = pkt[10]<<8+pkt[11]
    saddr = pkt[12:16]
    daddr = pkt[16:20]
    opts = pkt[20]<<16|pkt[21]<<8|pkt[22]
    payload = pkt[ihl:]

    # print(f"{saddr[0]}.{saddr[1]}.{saddr[2]}.{saddr[3]} -> {daddr[0]}.{daddr[1]}.{daddr[2]}.{daddr[3]} proto {proto}")

    if proto == 1:
        pkt[ihl:] = parseicmp(payload)
        (pkt[12:16], pkt[16:20]) = (pkt[16:20], pkt[12:16])
        pkt[10:12] = [0,0]
        chk = calcchk(pkt)
        pkt[10] = chk>>8
        pkt[11] = chk & 0xff
        print( " sending "+" ".join(["%.2x"%x for x in pkt]))
        return pkt
    elif proto == 6:
        parsetcp(payload)
        return None
    elif proto == 17:
        parseudp(payload)
        return None

def parse6(pkt):
    return None

tun = TunTapDevice()
tun.addr = '192.168.210.1'
tun.dstaddr = '192.168.210.2'
tun.netmask = '255.255.255.252'
tun.mtu = 1500
tun.up()

while True:
    buf = tun.read(tun.mtu)
    # pkt = ["%.2x "%c for c in list(buf)]
    pkt = list(buf)
    ethertype = pkt[2] << 8 | pkt[3]
    flags = pkt[0] << 8 | pkt[1]
    payload = pkt[4:]
    if ethertype == 0x0800:
        print("Got IPv4 packet")
        ret = parse4(payload)
        if ret is not None:
            buf = [0x00,0x00,0x08,0x00]+ret
            # print( " sending "+" ".join(["%.2x"%x for x in buf]))
            tun.write(bytes(buf))
    elif ethertype == 0x86DD:
        # print("Got IPv6 packet")
        parse6(payload)
    else:
        # print("Got unknown packet type")
        pass
