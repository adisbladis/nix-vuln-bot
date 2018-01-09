#!/usr/bin/env python3
import subprocess
import socket
import json
import ssl
import re
import os


R_CVE = re.compile(r'CVE-\d{4}-\d+', flags=re.IGNORECASE)


def notify_irc(
        server='irc.freenode.net',
        nick='vulnix',
        channel='#nixos-dev',
        tls=True,
        port=6697,
        messages=None):

    if not messages:
        return

    sock = socket.socket()
    if tls:
        sock = ssl.wrap_socket(
            sock, cert_reqs=ssl.CERT_NONE,
            ssl_version=ssl.PROTOCOL_TLSv1_2)

    def send(command):
        return sock.send(('%s\r\n' % command).encode())

    sock.connect((server, port))
    send('NICK %s' % (nick))
    send('USER %s %s bla :%s' % (nick, server, nick))
    send('JOIN :%s' % channel)

    for m in messages:
        send('PRIVMSG %s :%s' % (channel, m))

    send('INFO')

    while True:
        data = sock.recv(4096)
        if not data:
            raise RuntimeError('Received empty data')

        # Assume INFO reply means we are done
        if b'End of /INFO list' in data:
            break

        if data.startswith(b'PING'):
            sock.send(data.replace(b'PING', b'PONG'))

    sock.send(b'QUIT')
    sock.close()


def run_command(command, extra_env=None):
    env = {**os.environ, **(extra_env or {})}

    p = subprocess.Popen(
        command, env=env, stdout=subprocess.PIPE)
    if p.wait() != 0:
        raise RuntimeError(f'Subprocess returned {p.wait()}')

    return p.communicate()[0].decode().strip()


def instantiate_drv(git_rev):
    extra_env = {
        'NIX_PATH': f'nixpkgs=https://github.com/NixOS/nixpkgs/archive/{git_rev}.tar.gz'  # noqa
    }

    release_combined = run_command([
        'nix-instantiate',
        '--find-file',
        'nixpkgs/nixos/release-combined.nix'
    ], extra_env)
    drv = run_command([
        'nix-instantiate',
        release_combined.strip(),
    ], extra_env)
    return drv


def find_vulns(git_rev, whitelist):
    vulns = json.loads(subprocess.run(
        [
            'vulnix', '--json',
            instantiate_drv(git_rev)
        ],
        stdout=subprocess.PIPE).stdout.decode())

    for pkg in vulns:
        affected_by = set(pkg['affected_by']) - whitelist
        pkg['affected_by'] = affected_by
        if affected_by:
            yield pkg


def whitelist_read(git_rev):
    with open(f'./whitelists/{git_rev}') as f:
        return set(m.group(0).upper() for m in R_CVE.finditer(f.read()))


def whitelist_write(git_rev, whitelist):
    with open(f'./whitelists/{git_rev}', 'w') as f:
        f.write('\n'.join(whitelist))


def notification_format(git_rev, pkg):
    affected_by_str = ' '.join(pkg['affected_by'])
    return f'{pkg["pname"]}: affected by {affected_by_str} in {git_rev}'


if __name__ == '__main__':
    git_rev = 'master'

    whitelist = whitelist_read(git_rev)
    vulns_json = list(find_vulns(git_rev, whitelist))
    if not vulns_json:
        exit(0)

    new_cves = set()
    for pkg in vulns_json:
        for cve in pkg['affected_by']:
            whitelist.add(cve)

        new_cves.update(pkg['affected_by'])

    notify_irc(
        messages=[
            notification_format(git_rev, pkg)
            for pkg in vulns_json
        ]
    )

    whitelist_write(git_rev, whitelist)
