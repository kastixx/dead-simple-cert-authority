#!/usr/bin/env python3

import os, sys, argparse

from certman import *

def command_line_add_common_request_args(cmd_parser):
    ca_parser.add_argument("-c", "--common-name", "--cn",
                           help="set Common Name (CN) field of the Distinguished Name (DN), "
                                "certificate name is used by default")
    ca_parser.add_argument("-U", "--organization-unit", "--ou",
                           help="set Organization Unit (OU) field of the DN, "
                                "can be specified several times",
                           action="append")
    ca_parser.add_argument("-O", "--organization", "--org",
                           help="set Organization Unit (OU) field of the DN")
    ca_parser.add_argument("-L", "--locality",
                           help="set Locality (L) field of the DN")
    ca_parser.add_argument("-S", "--state",
                           help="set State (ST) field of the DN")
    ca_parser.add_argument("-C", "--country",
                           help="set Country (C) field of the DN")
    ca_parser.add_argument("-E", "--email",
                           help="set emailAddress field of the DN")
    ca_parser.add_argument("-b", "--bits", metavar='N',
                           help="use key of N bits long, N = 2048 or 4096 (default)",
                           type=int, choices=(2048, 4096), default=4096)
    ca_parser.add_argument("-H", "--hash",
                           help="use specified hash algorithm, either sha256 or sha512 (default)",
                           choices=('sha256', 'sha512'), default='sha512')
    ca_parser.add_argument("-d", "--days",
                           help="set certificate validity period in days, default is 3650",
                           type=int, default=3650)


def command_line_parser():
    parser = argparse.ArgumentParser(description="Simple file-based certificate tree manager")
    parser.add_argument("-s", "--store",
                        help="certificate store path, current directory by default")
    subparsers = parser.add_subparsers(description="Utility commands", dest="command")

    ca_parser = subparsers.add_parser("cert", help="create new server/client certificate")
    command_line_add_common_request_args(ca_parser)
    ca_parser.add_argument("-n", "--name", metavar="DOMAIN_NAME",
                           help="domain name that is authenticated by this certificate, "
                                "can be specified several times for multiple aliases, "
                                "CN is used as a single domain name if none are specified",
                           action="append")
    ca_parser.add_argument("-a", "--ca", metavar="CA_NAME",
                           help="sign the new certificate with a CA that already exists "
                                "in the certificate store (the default is to create a "
                                "self-signed certificate)")
    ca_parser.add_argument("basename", metavar="NAME",
                           help="a name that identifies this certificate, "
                                "must be unique among all certificates within the store "
                                "signed by the same CA")

    ca_parser = subparsers.add_parser("ca", help="create new CA certificate")
    command_line_add_common_request_args(ca_parser)
    ca_parser.add_argument("-a", "--ca", metavar="CA_NAME",
                           help="sign the new certificate with another CA that already exists "
                                "in the certificate store (the default is to create a "
                                "root self-signed CA)")
    ca_parser.add_argument("basename", metavar="NAME",
                           help="a name that identifies this certificate, "
                                "must be unique among all CA certificates within the store")

    return parser


def create_store(args):
    return Store(root_dir=args.store)


def build_request(args, is_ca=False):
    common_name = args.common_name or args.basename

    if is_ca:
        domain_names = None
    else:
        domain_names = args.name or [ common_name ]

    dn = DNSection(country=args.country,
                   state=args.state,
                   locality=args.locality,
                   organization=args.organization,
                   organization_units=args.organization_unit,
                   common_name=common_name,
                   email_address=args.email)

    req = Request(dn, is_ca=is_ca, domain_names=domain_names,
                  bits=args.bits, days=args.days, hash_algo=args.hash)

    return req


def create_cert(args, is_ca=False):
    openssl = OpenSSL()
    store = create_store(args)
    req = build_request(args, is_ca=is_ca)
    if args.ca:
        ca_context = Context(args.ca, is_ca=True)
        context = Context(args.basename, is_ca=is_ca, ca_context=ca_context)
        ca_paths = store.get_context_paths(ca_context)
        store.verify_exists(ca_context, paths=ca_paths, check_cert=True, check_key=True)
        store.verify_exists(context, check_cert=True, check_key=True,
                            check_rsa_key=True, check_req=True, inverted_check=True)
        openssl.signed(context, req, ca_paths)

    else:
        context = Context(args.basename, is_ca=is_ca)
        store.verify_exists(context, check_cert=True, check_key=True,
                            check_rsa_key=True, check_req=True, inverted_check=True)
        openssl.self_signed(context, req)

    openssl.add_rsa_key(context)
    store.store(context, require_rsa=True)


def handle_cert(args):
    create_cert(args, is_ca=False)


def handle_ca(args):
    create_cert(args, is_ca=True)


def main():
    parser = command_line_parser()
    args = parser.parse_args()

    try:
        if args.command == 'ca':
            handle_ca(args)
        elif args.command == 'cert':
            handle_ca(args)
        else:
            parser.print_usage()
            sys.exit(127)

    except Exception as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
