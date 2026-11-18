"""Compile three owner lists offline. Python standard library only; never execute input."""
import argparse
import ipaddress
import json
from pathlib import Path
import re

GROUPS = ('claude', 'core', 'default')
MAX_ENTRIES = 2000
MAX_BYTES = 262144
DOMAIN = re.compile(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
PROCESS_TYPES = {'PROCESS-NAME', 'PROCESS-NAME-REGEX', 'PROCESS-PATH-REGEX', 'IN-NAME'}
IP_TYPES = {'IP-CIDR', 'IP-CIDR6'}


def parse_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ('%' in value or not address.is_global or address.is_multicast or address.is_reserved
            or getattr(address, 'ipv4_mapped', None) is not None):
        raise ValueError('Only public unicast IP addresses can be overridden: ' + value)
    return address


def parse(text):
    if len(text.encode()) > MAX_BYTES:
        raise ValueError('Input list exceeds size limit')
    result = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ',' not in line:
            address = parse_address(line)
            if address is not None:
                kind = 'IP-CIDR' if address.version == 4 else 'IP-CIDR6'
                result.append((kind, address))
                continue
        parts = line.split(',') if ',' in line else ['DOMAIN-SUFFIX', line]
        if len(parts) != 2 or parts[0] not in ('DOMAIN', 'DOMAIN-SUFFIX'):
            raise ValueError('Use a single public IP, a domain, DOMAIN,domain or DOMAIN-SUFFIX,domain')
        kind, host = parts[0], parts[1].strip().lower().rstrip('.')
        if not DOMAIN.fullmatch(host):
            raise ValueError('Invalid domain: ' + host)
        if any(host == local or host.endswith('.' + local) for local in ('lan', 'local', 'home.arpa', 'localhost')):
            raise ValueError('Local domains cannot be overridden')
        result.append((kind, host))
    if len(result) > MAX_ENTRIES:
        raise ValueError('Input list exceeds entry limit')
    return list(dict.fromkeys(result))


def compile_lists(texts, catalog):
    if catalog.get('version') != 1:
        raise ValueError('Unsupported business catalog')
    entries = {group: parse(texts[group]) for group in GROUPS}
    anchors = {anchor: name for name, family in catalog['families'].items() for anchor in family['anchors']}
    assignments = {}
    ip_owners = {}
    expanded = {group: [] for group in GROUPS}
    for group in GROUPS:
        for kind, host in entries[group]:
            if kind in IP_TYPES:
                if ip_owners.setdefault(host, group) != group:
                    raise ValueError('IP address appears in multiple groups: ' + str(host))
                expanded[group].append(f'{kind},{host}/{host.max_prefixlen},no-resolve')
                continue
            labels = host.split('.')
            matches = {anchors[suffix] for i in range(len(labels)) if (suffix := '.'.join(labels[i:])) in anchors}
            for name in matches:
                if name in assignments and assignments[name] != group:
                    raise ValueError('Business family appears in multiple groups: ' + name)
                assignments[name] = group
            expanded[group].append(kind + ',' + host)
    for name, group in assignments.items():
        family_rules = catalog['families'][name]['rules']
        for rule in family_rules:
            kind, value, *_ = rule.split(',')
            if kind in IP_TYPES:
                network = ipaddress.ip_network(value)
                for address, owner in ip_owners.items():
                    if owner != group and address in network:
                        raise ValueError(f'IP address {address} overlaps {name} network {network} in {group}')
        expanded[group].extend(family_rules)
    # Check the actual expanded domain surface, including overlaps with ordinary entries.
    domain_owners = {}
    keywords = []
    for group, rules in expanded.items():
        for rule in rules:
            kind, value, *_ = rule.split(',')
            if kind in ('DOMAIN', 'DOMAIN-SUFFIX'):
                previous = domain_owners.setdefault((kind, value), group)
                if previous != group:
                    raise ValueError('Conflicting expanded domain: ' + value)
            elif kind == 'DOMAIN-KEYWORD':
                keywords.append((value, group))
    # Suffix lookup avoids a quadratic scan at the input limit.
    for (kind, host), group in domain_owners.items():
        labels = host.split('.')
        for i in range(len(labels)):
            suffix = '.'.join(labels[i:])
            if domain_owners.get(('DOMAIN-SUFFIX', suffix), group) != group:
                raise ValueError('Conflicting expanded suffix: ' + suffix)
        for keyword, owner in keywords:
            if owner != group and keyword in host:
                raise ValueError('Conflicting shared keyword: ' + keyword)
    outputs = {}
    for group, rules in expanded.items():
        rules = list(dict.fromkeys(rules))
        for platform in ('clash', 'ios', 'business'):
            selected = []
            for rule in rules:
                kind = rule.split(',')[0]
                process = kind in PROCESS_TYPES
                if (platform == 'business') != process:
                    continue
                if platform == 'ios' and kind == 'IP-CIDR6':
                    rule = rule.replace('IP-CIDR6,', 'IP6-CIDR,', 1)
                selected.append(rule)
            body = '# Generated; edit ../' + group + '.list instead.\n' + ''.join(rule + '\n' for rule in selected)
            if len(body.encode()) > 1048576:
                raise ValueError('Compiled rule set exceeds client size limit')
            outputs[group + '.' + platform + '.list'] = body
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    root = args.root
    # Validate the complete batch before touching any previous output.
    outputs = compile_lists({group: (root / (group + '.list')).read_text() for group in GROUPS},
                            json.loads((root / 'catalog.json').read_text()))
    directory = root / 'generated'
    directory.mkdir(exist_ok=True)
    for name, body in outputs.items():
        destination = directory / name
        if not destination.exists() or destination.read_text() != body:
            pending = directory / (name + '.pending')
            pending.write_text(body)
            pending.replace(destination)
    print('Compiled nine rule sets; all inputs validated')


if __name__ == '__main__':
    main()
