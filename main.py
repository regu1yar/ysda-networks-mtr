#!/usr/bin/env python3

import argparse
import sys

from curses import wrapper
from enum import Enum

from scapy.all import *
from prettytable import PrettyTable, ALL


class IPVersion(Enum):
    ipv4 = 'ipv4'
    ipv6 = 'ipv6'

    def __str__(self):
        return self.value


class WrappeeProto(Enum):
    icmp = 'icmp'
    udp = 'udp'
    tcp = 'tcp'

    def __str__(self):
        return self.value


def get_ip_packet(p):
    if IP in p:
        return p[IP]
    elif IPv6 in p:
        return p[IPv6]
    else:
        raise NotImplementedError('IP versions 4 and 6 are supported only')


class HopState(object):
    def __init__(self):
        self.hosts = set()
        self.sent = 0
        self.received = 0

    def receive(self, query, answer):
        self.sent += 1
        if answer is None:
            return
        self.hosts.add(get_ip_packet(answer).src)
        self.received += 1

    def get_stats(self):
        return [
            '\n'.join(self.hosts),                          # hosts
            (1 - (self.received / self.sent)) * 100,        # loss (%)
            self.sent,                                      # sent
        ]


class MTRState(object):
    def __init__(self, max_ttl):
        self._max_ttl = max_ttl
        self._target_dst = None
        self._is_reached = False
        self.total_ttl = 1
        self.hops = []

    def receive(self, query, answer):
        if self._target_dst is None:
            self._target_dst = get_ip_packet(query).dst
        if not self._is_reached and answer is not None:
            self._is_reached = self._target_dst == get_ip_packet(answer).src
        orig_ttl = None
        if IP in query:
            orig_ttl = query[IP].ttl
        elif IPv6 in query:
            orig_ttl = query[IPv6].hlim
        else:
            raise NotImplementedError('IP versions 4 and 6 are supported only')
        if len(self.hops) < orig_ttl:
            self.hops.append(HopState())
        self.hops[orig_ttl-1].receive(query, answer)

    def __str__(self):
        table = PrettyTable(['Hop No.', 'Hosts', 'Loss (%)', 'Sent'])
        table.hrules=ALL
        table.align['Hosts'] = 'l'
        prev_loss = 0
        for hop_no, state in enumerate(self.hops):
            hop_stats = state.get_stats()
            hop_stats[1], prev_loss = max(0, hop_stats[1] - prev_loss), hop_stats[1]
            hop_stats[1] = '{:.2f}'.format(hop_stats[1])
            table.add_row([hop_no + 1] + hop_stats)
        return str(table)

    def _can_prolong(self):
        if len(self.hops) < 2:
            return True
        return len(self.hops[-1].hosts) > 0 or len(self.hops[-2].hosts) > 0

    def prolong_if_needed(self):
        if not self._is_reached and self._can_prolong() and self.total_ttl < self._max_ttl:
            self.total_ttl += 1

    def is_reached(self):
        return self._is_reached or self.total_ttl == self._max_ttl


def build_datagram_packet(args, dst_host, ttl):
    ip_proto = None
    wrappee_packet = None

    if args.ip == IPVersion.ipv4:
        ip_proto = IP(dst=dst_host, ttl=ttl)
    elif args.ip == IPVersion.ipv6:
        ip_proto = IPv6(dst=dst_host, hlim=ttl)
    else:
        raise NotImplementedError(f'{args.ip} ip protocol version is not supported')

    if args.wrap == WrappeeProto.icmp:
        if args.ip == IPVersion.ipv4:
            wrappee_packet = ICMP()
        elif args.ip == IPVersion.ipv6:
            wrappee_packet = ICMPv6EchoRequest()
        return ip_proto/wrappee_packet
    elif args.wrap == WrappeeProto.udp:
        wrappee_packet = UDP(dport=30000)
        raw_data = Raw(load='0'*32)
        return ip_proto/wrappee_packet/raw_data
    elif args.wrap == WrappeeProto.tcp:
        wrappee_packet = TCP(dport=80, seq=0, flags='S')
        return ip_proto/wrappee_packet


def display(stdscr, text):
    stdscr.clear()
    stdscr.addstr(text)
    stdscr.scrollok(True)
    stdscr.refresh()


def run_mtr(stdscr, args):
    stdscr.nodelay(True)
    stdscr.clear()
    dst_host = args.host
    timeout = args.timeout
    max_ttl = args.max_ttl
    assert max_ttl
    is_reachable = True
    state = MTRState(max_ttl)
    while True:
        cur_ttl = None
        if state.is_reached():
            cur_ttl = (1, state.total_ttl)
        else:
            cur_ttl = state.total_ttl
        req = build_datagram_packet(args, dst_host, cur_ttl)
        ans, unans = sr(req, timeout=timeout, verbose=0)
        if ans:
            for a in ans:
                state.receive(a.query, a.answer)
        if unans:
            if state.total_ttl == 1:
                is_reachable = False
                break
            for u in unans:
                state.receive(u, None)
        display(stdscr, f'{state}\n')
        try:
            if stdscr.getkey() == 'q':
                break
        except:
            pass
        state.prolong_if_needed()
    if not is_reachable:
        display(stdscr, 'Address is unreachable')
        stdscr.nodelay(False)
        stdscr.getch()
        exit(1)


def main():
    parser = argparse.ArgumentParser(description='MTR tool analogue.')
    parser.add_argument('-i', '--ip', type=IPVersion, choices=list(IPVersion),
                        help='IP protocol version', default=IPVersion.ipv4)
    parser.add_argument('-w', '--wrap', type=WrappeeProto, choices=list(WrappeeProto),
                        help='L3/L4 protocol to use', default=WrappeeProto.icmp)
    parser.add_argument('-t', '--timeout', type=int, help='number of seconds to wait responses', default=1)
    parser.add_argument('--max-ttl', type=int, help='max TTL for IP packets', default=16)
    parser.add_argument('host', help='destination host address')
    args = parser.parse_args()
    wrapper(run_mtr, args)


if __name__ == '__main__':
    main()
