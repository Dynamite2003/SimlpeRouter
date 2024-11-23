#!/usr/bin/env python
'''
Autograde script, includes all public and private test cases
'''

from ast import parse
import mininet.net
import mininet.node

from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.util import quietRun
from mininet.moduledeps import pathCheck

from sys import exit
import os.path
from subprocess import Popen, STDOUT, PIPE, check_call

from run import IP_SETTING, start_topo, stop_topo
import re, time, os, sys, logging, Ice, traceback

log = logging.getLogger("Auto Grader")
logging.basicConfig(stream=sys.stderr)
log.setLevel(logging.DEBUG)  # can be set to CRITICAL, ERROR, WARNING, INFO, DEBUG, NOTSET, etc.

score = 0
details = []

# Updated WRONG_IP as per user instruction
WRONG_IP = "122.122.2.100"
# List of router interfaces
ROUTER_INTERFACES = ["sw0-eth1", "sw0-eth2", "sw0-eth3"]

def init_communicator():
    global tester
    slice_dir = Ice.getSliceDir()
    if not slice_dir:
        log.error(sys.argv[0] + ': Slice directory not found.')
        sys.exit(1)

    Ice.loadSlice("", ["-I%s" % slice_dir, "core/pox.ice"])

    import pox
    communicator = None
    tester = None
    try:
        communicator = Ice.initialize(sys.argv)
        base = communicator.stringToProxy("Tester:tcp -h 127.0.0.1 -p 65500")
        tester = pox.TesterPrx.checkedCast(base)
        if not tester:
            raise RuntimeError("Invalid Proxy")
    except:
        traceback.print_exc()
        sys.exit(1)
    return communicator, tester

def destroy_communicator(communicator):
    try:
        communicator.destroy()
    except:
        traceback.print_exc()
        sys.exit(1)

def parse_ping(result):
    '''
    Parse ping output string, return packets sent, received
    '''
    r = r'(\d+) packets transmitted, (\d+) received'
    m = re.search(r, result)
    if m is None:
        log.error('*** Error: could not parse ping output: "%s"\n' % result)
        return 1, 0
    sent, received = int(m.group(1)), int(m.group(2))
    return sent, received

def get_arp_line():
    global tester
    result = tester.getArp()
    log.debug("ARP CACHE TABLE: \n{}\n".format(result))
    lines = len(result.splitlines()) - 4  # empty arp cache has 4 lines in practice
    return lines

def test_ping_reachability_public(net):
    '''
    Test 1.a, 1.b, 1.c
    Pings from client, server1, server2 to all other hosts including non-existing host
    '''
    global score, details
    print('\n*** Conducting Ping Reachability Public Tests.\n')

    hosts = ['client', 'server1', 'server2']
    src_hosts = [net.get(host) for host in hosts]
    dest_hosts = [host for host in net.hosts]

    for src in src_hosts:
        ping_success = True
        for dest in dest_hosts:
            if src == dest:
                continue
            result = src.cmd("ping -c 1 {}".format(dest.IP()))
            sent, received = parse_ping(result)
            log.debug(result)
            log.debug("sent = {}, received = {}".format(sent, received))
            if received < sent:
                log.error("Ping from {} to {} failed".format(src.name, dest.name))
                ping_success = False
        # Ping non-existing host
        result = src.cmd("ping -c 1 {}".format(WRONG_IP))
        sent, received = parse_ping(result)
        log.debug(result)
        log.debug("Ping to non-existing host {}: sent = {}, received = {}".format(WRONG_IP, sent, received))
        if received > 0:
            log.error("Ping to non-existing IP {} from {} unexpectedly succeeded".format(WRONG_IP, src.name))
            ping_success = False
        else:
            log.info("Ping to non-existing IP {} from {} failed as expected".format(WRONG_IP, src.name))
        
        if ping_success:
            score += 5
        else:
            log.error("*** Fail to ping from {}: -5 pts".format(src.name))
            details.append("*** Fail to ping from {}: -5 pts".format(src.name))

def test_ping_ARP_cache_public(net):
    '''
    Test 1.e, 1.f
    a) Ping between selected hosts, check ARP cache
    b) Ping from client to server1, after 40 seconds, ARP cache should be empty
    '''
    global score, details
    print('\n*** Conducting Ping ARP Cache Public Tests.\n')

    client = net.get('client')
    server1 = net.get('server1')
    server2 = net.get('server2')

    # Test 1.e: Ping between selected hosts and check ARP cache
    client.cmd("ping -c 1 {}".format(server1.IP()))
    client.cmd("ping -c 1 {}".format(server2.IP()))
    lines = get_arp_line()
    log.debug("ARP cache has {} entries after client pings server1 and server2".format(lines))
    if lines != 2:
        log.info("Have {} entries in ARP cache after client pings server1 and server2, 2 expected".format(lines))
        log.error("*** Fail to maintain ARP cache entries properly: -5 pts")
        details.append("*** Fail to maintain ARP cache entries properly: -5 pts")
    else:
        score += 5

    # Test 1.f: After 40 seconds, ARP cache should be empty
    time.sleep(40)
    lines = get_arp_line()
    log.debug("ARP cache has {} entries after 40 seconds.".format(lines))
    if lines != 0:
        log.error("*** Fail to empty ARP cache after 40 seconds: -5 pts")
        details.append("*** Fail to empty ARP cache after 40 seconds: -5 pts")
    else:
        score += 5

def test_ping_non_existing_private(net):
    '''
    Test 1.g, 1.h (Private)
    a) Ping non-existing IP, router sends proper ARP requests
    b) Receive host unreachable message
    '''
    global score, details
    print('\n*** Conducting Ping Non-Existing Private Tests.\n')

    client = net.get('client')
    router = net.get('sw0')  # Assuming 'sw0' is the router

    # Test 1.g: Ping non-existing IP and check router sends ARP requests
    result = client.cmd("ping -c 1 {}".format(WRONG_IP))
    log.debug(result)
    if "Host Unreachable" not in result and "Destination Host Unreachable" not in result:
        log.error("*** Router did not send proper ARP requests when pinging non-existing IP: -5 pts")
        details.append("*** Router did not send proper ARP requests when pinging non-existing IP: -5 pts")
    else:
        score += 5

    # Test 1.h: Ping non-existing IP and expect host unreachable message
    if "Host Unreachable" in result or "Destination Host Unreachable" in result:
        score += 5
    else:
        log.error("*** Did not receive Host Unreachable message when pinging non-existing IP: -5 pts")
        details.append("*** Did not receive Host Unreachable message when pinging non-existing IP: -5 pts")

def test_ping_TTL_private(net):
    '''
    Test 1.d (Private)
    Ping responses have proper TTLs
    '''
    global score, details
    print('\n*** Conducting Ping TTL Private Test.\n')

    client = net.get('client')
    server1 = net.get('server1')

    # Ping from client to server1 and capture TTL
    result = client.cmd("ping -c 1 {}".format(server1.IP()))
    log.debug(result)
    ttl = None
    m = re.search(r'ttl=(\d+)', result)
    if m:
        ttl = int(m.group(1))
        log.debug("Received TTL: {}".format(ttl))
    else:
        log.error("*** Could not find TTL in ping response: -10 pts")
        details.append("*** Could not find TTL in ping response: -10 pts")
        return

    # Assuming initial TTL is 64, adjust based on network hops
    expected_ttl = 64 - 1  # 1 hop to router
    if ttl == expected_ttl:
        score += 10
    else:
        log.error("*** Incorrect TTL value. Expected {}, got {}: -10 pts".format(expected_ttl, ttl))
        details.append("*** Incorrect TTL value. Expected {}, got {}: -10 pts".format(expected_ttl, ttl))

def parse_traceroute(result):
    '''
    Parse traceroute result string
    Return tuple of (routes, error):
        routes: list of all IP string representation in route, None for unknown IP
        error: count number of errors shown in result (!H, !N, !P, etc)
    '''
    error = len(re.findall(r'![HNPSFXVC0-9]', result))
    routes = []
    ip_pattern = r'\((\d+\.\d+\.\d+\.\d+)\)'  # match IP in traceroute entry
    for line in result.splitlines():
        m = re.search(ip_pattern, line)
        if m:
            routes.append(m.group(1))
        else:
            routes.append(None)
    return routes, error

def test_traceroute_public(net):
    '''
    Test 2.a, 2.b, 2.c
    Traceroute from client, server1, server2 to all other hosts including non-existing host
    '''
    global score, details
    print('\n*** Conducting Traceroute Public Tests.\n')

    hosts = ['client', 'server1', 'server2']
    src_hosts = [net.get(host) for host in hosts]
    dest_hosts = [host for host in net.hosts] + [WRONG_IP]

    for src in src_hosts:
        traceroute_success = True
        for dest in dest_hosts:
            if src.name == dest.name:
                continue
            result = src.cmd("traceroute -n -q 1 {}".format(dest if isinstance(dest, str) else dest.IP()))
            routes, error = parse_traceroute(result)
            log.debug(result)
            log.debug("routes = {}, error = {}".format(routes, error))
            if dest == WRONG_IP:
                if error == 0:
                    log.error("Traceroute to non-existing IP {} from {} unexpectedly succeeded".format(WRONG_IP, src.name))
                    traceroute_success = False
            else:
                # Assuming single hop via router
                if len(routes) < 2 or routes[0] not in [IP_SETTING[iface] for iface in ROUTER_INTERFACES] or routes[1] != dest.IP():
                    log.error("Traceroute from {} to {} failed".format(src.name, dest.name))
                    traceroute_success = False
        if traceroute_success:
            score += 5
        else:
            log.error("*** Fail to traceroute from {}: -5 pts".format(src.name))
            details.append("*** Fail to traceroute from {}: -5 pts".format(src.name))

def test_traceroute_router_private(net):
    '''
    Test 2.d (Private)
    Traceroute from client to router’s interfaces (get 1 line)
    '''
    global score, details
    print('\n*** Conducting Traceroute to Router Interfaces Private Test.\n')

    client = net.get('client')
    router_ips = [IP_SETTING[iface] for iface in ROUTER_INTERFACES]

    for router_ip in router_ips:
        result = client.cmd("traceroute -n -q 1 {}".format(router_ip))
        routes, error = parse_traceroute(result)
        log.debug(result)
        log.debug("routes = {}, error = {}".format(routes, error))
        if len(routes) != 1 or routes[0] != router_ip:
            log.error("Traceroute from client to router interface {} failed".format(router_ip))
            details.append("Traceroute from client to router interface {} failed: -10 pts".format(router_ip))
        else:
            score += 2.5  # 10 pts divided by number of router interfaces (assuming 4)
    # Adjust the score increment based on number of interfaces
    # For simplicity, awarding full 10 pts if all interfaces pass
    total_interfaces = len(router_ips)
    passed = 0
    for router_ip in router_ips:
        result = client.cmd("traceroute -n -q 1 {}".format(router_ip))
        routes, error = parse_traceroute(result)
        if len(routes) == 1 and routes[0] == router_ip:
            passed += 1
    if passed == total_interfaces:
        score += 10
    else:
        log.error("*** Fail to traceroute to all router interfaces: -10 pts")
        details.append("*** Fail to traceroute to all router interfaces: -10 pts")

def test_download_small_file_public(net):
    '''
    Test 3.a
    Download a small file (~1 KB) from any server through HTTP
    '''
    global score, details
    print('\n*** Conducting File Downloading Small File Public Test.\n')

    client = net.get('client')
    server = net.get('server1')  # Choosing server1 for testing

    # Create a small file on the server
    small_file = "small_file.txt"
    server.cmd("echo 'This is a small test file.' > /tmp/{}".format(small_file))

    # Start a simple HTTP server on the server
    server.cmd("nohup python3 -m http.server 80 --directory /tmp > /dev/null 2>&1 &")
    time.sleep(2)  # Wait for the server to start

    # Download the small file
    wget_cmd = "wget -q -O /tmp/downloaded_small_file.txt http://{}/{}".format(server.IP(), small_file)
    client.cmd(wget_cmd)
    log.debug("Client downloaded small file using command: {}".format(wget_cmd))

    # Compare the files
    diff_result = client.cmd("diff /tmp/downloaded_small_file.txt /tmp/{}".format(small_file))
    if diff_result == "":
        log.info("Successfully downloaded small file from {} to {}".format(server.name, client.name))
        score += 5
    else:
        log.error("*** Fail to download small file from HTTP server: -5 pts")
        details.append("*** Fail to download small file from HTTP server: -5 pts")

    # Cleanup
    client.cmd("rm -f /tmp/downloaded_small_file.txt")
    server.cmd("pkill -f 'python3 -m http.server'")  # Stop the HTTP server

def test_download_large_file_private(net):
    '''
    Test 3.b (Private)
    Download a large file (~10 MB) from any server through HTTP
    '''
    global score, details
    print('\n*** Conducting File Downloading Large File Private Test.\n')

    client = net.get('client')
    server = net.get('server2')  # Choosing server2 for testing

    # Create a large file on the server
    large_file = "large_file.bin"
    server.cmd("dd if=/dev/urandom of=/tmp/{} bs=1M count=10".format(large_file))

    # Start a simple HTTP server on the server
    server.cmd("nohup python3 -m http.server 80 --directory /tmp > /dev/null 2>&1 &")
    time.sleep(2)  # Wait for the server to start

    # Download the large file
    wget_cmd = "wget -q -O /tmp/downloaded_large_file.bin http://{}/{}".format(server.IP(), large_file)
    client.cmd(wget_cmd)
    log.debug("Client downloaded large file using command: {}".format(wget_cmd))

    # Compare the files
    diff_result = client.cmd("diff /tmp/downloaded_large_file.bin /tmp/{}".format(large_file))
    if diff_result == "":
        log.info("Successfully downloaded large file from {} to {}".format(server.name, client.name))
        score += 10
    else:
        log.error("*** Fail to download large file from HTTP server: -10 pts")
        details.append("*** Fail to download large file from HTTP server: -10 pts")

    # Cleanup
    client.cmd("rm -f /tmp/downloaded_large_file.bin")
    server.cmd("rm -f /tmp/{}".format(large_file))
    server.cmd("pkill -f 'python3 -m http.server'")  # Stop the HTTP server

def test_traceroute_public(net):
    '''
    Test 2.a, 2.b, 2.c
    Traceroute from client, server1, server2 to all other hosts including non-existing host
    '''
    global score, details
    print('\n*** Conducting Traceroute Public Tests.\n')

    hosts = ['client', 'server1', 'server2']
    src_hosts = [net.get(host) for host in hosts]
    dest_hosts = [host for host in net.hosts]

    for src in src_hosts:
        traceroute_success = True
        for dest in dest_hosts:
            if src == dest:
                continue
            result = src.cmd("traceroute -n -q 1 {}".format(dest.IP()))
            routes, error = parse_traceroute(result)
            log.debug(result)
            log.debug("routes = {}, error = {}".format(routes, error))
            # Assuming single hop via router
            expected_router_ip = IP_SETTING['sw0-eth1']  # Assuming sw0-eth1 is the router's interface
            if len(routes) < 2 or routes[0] != expected_router_ip or routes[1] != dest.IP():
                log.error("Traceroute from {} to {} failed".format(src.name, dest.name))
                traceroute_success = False
        # Traceroute to non-existing host
        result = src.cmd("traceroute -n -q 1 {}".format(WRONG_IP))
        routes, error = parse_traceroute(result)
        log.debug(result)
        log.debug("Traceroute to non-existing IP {}: routes = {}, error = {}".format(WRONG_IP, routes, error))
        if error == 0:
            log.error("Traceroute to non-existing IP {} from {} unexpectedly succeeded".format(WRONG_IP, src.name))
            traceroute_success = False
        else:
            log.info("Traceroute to non-existing IP {} from {} failed as expected".format(WRONG_IP, src.name))
        
        if traceroute_success:
            score += 5
        else:
            log.error("*** Fail to traceroute from {}: -5 pts".format(src.name))
            details.append("*** Fail to traceroute from {}: -5 pts".format(src.name))

def test_traceroute_private(net):
    '''
    Test 2.d (Private)
    Traceroute from client to router’s interfaces (get 1 line)
    '''
    global score, details
    print('\n*** Conducting Traceroute to Router Interfaces Private Test.\n')

    client = net.get('client')
    router_ips = [IP_SETTING[iface] for iface in ROUTER_INTERFACES]

    traceroute_success = True
    for router_ip in router_ips:
        result = client.cmd("traceroute -n -q 1 {}".format(router_ip))
        routes, error = parse_traceroute(result)
        log.debug(result)
        log.debug("routes = {}, error = {}".format(routes, error))
        if len(routes) != 1 or routes[0] != router_ip:
            log.error("Traceroute from client to router interface {} failed".format(router_ip))
            traceroute_success = False
    if traceroute_success:
        score += 10
    else:
        log.error("*** Fail to traceroute to router interfaces: -10 pts")
        details.append("*** Fail to traceroute to router interfaces: -10 pts")

def test_download_public(net):
    '''
    Test 3.a
    Download a small file (~1 KB) from any server through HTTP
    '''
    test_download_small_file_public(net)

def test_download(net):
    '''
    Wrapper function to conduct both public and private download tests
    '''
    test_download_public(net)
    test_download_large_file_private(net)

def test(net):
    '''
    Conduct all tests
    '''
    # Public Tests
    test_ping_reachability_public(net)
    test_ping_ARP_cache_public(net)
    test_traceroute_public(net)
    test_download_public(net)

    # Private Tests
    test_ping_non_existing_private(net)
    test_ping_TTL_private(net)
    test_traceroute_private(net)
    test_download_large_file_private(net)

def main():
    global tester
    net = start_topo()
    communicator, tester = init_communicator()
    try:
        test(net)
    except Exception as e:
        log.error("An exception occurred during testing: {}".format(e))
        traceback.print_exc()
    finally:
        stop_topo(net)
        destroy_communicator(communicator)

if __name__ == '__main__':
    setLogLevel('info')
    main()
    print("\nYour tests score is {}/85 pts".format(score))
    print("THIS IS NOT YOUR FINAL SCORE !!!")
    # Write details to log file
    details.insert(0, "Your tests score is {}/85 pts".format(score))
    with open("details.log", "w") as f:
        for detail in details:
            f.write(detail + '\n')
