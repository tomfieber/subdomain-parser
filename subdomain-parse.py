#!/usr/bin/env python3

import argparse
import ipaddress


def run():
    parser = argparse.ArgumentParser(description="Parse subfinder output to find in-scope hosts")
    parser.add_argument('--scope', dest='scope', help='The scope file to expand', required=True)
    parser.add_argument('--hosts', dest='hosts', help='The file with subfinder output', required=True)
    parser.add_argument('--dnsx', dest='dnsx', default=False, action='store_true', help='Tells the application to process input in dnsx format.')

    options = parser.parse_args()

    scope_file = options.scope
    hosts_file = options.hosts
    dnsx = options.dnsx

    scope = []
    in_scope = set()
    out_scope = set()

    with open(scope_file, "r") as scope_f:
        data = scope_f.readlines()
        for line in data:
            line = line.strip()
            if '/' in line:
                netIpv4Address = ipaddress.ip_network(line)
                for ip in netIpv4Address:
                    scope.append(str(ip))
            else:
                scope.append(line)

    with open(hosts_file, "r") as hosts_f:
        data = hosts_f.readlines()
        for line in data:
            line = line.strip()
            if not dnsx:
                host, ip, _ = line.split(',')
                if ip in scope:
                    in_scope.add((ip, host))
                else:
                    out_scope.add((ip, host))
            else:
                host, ip = line.split()
                ip = ip.replace("[", "")
                ip = ip.replace("]", "")
                if ip in scope:
                    in_scope.add((ip, host))
                else:
                    out_scope.add((ip, host))

    print(f"\n[+] In-Scope Hosts")
    for host in in_scope:
        ip, host = host[0], host[1]
        print(f"{ip} {host}")

    print(f"\n\n[-] Out-of-Scope Hosts")
    for host in out_scope:
        ip, host = host[0], host[1]
        print(f"{ip} {host}")

if __name__ == "__main__":
    run()




