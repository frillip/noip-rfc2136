#!/usr/bin/python3

import sys
import json
import logging
import colorlog
import socket
import dns.update
import dns.query
import dns.tsigkeyring
import dns.resolver
from time import sleep
from aiohttp import web
from aiohttp_basicauth_middleware import basic_auth_middleware
import ssl
import os
from distutils.util import strtobool

# Logging Config
log_level = 'INFO'

# DNS config
dns_nameserver = '198.51.100.2'
dns_zone = 'example.com.'
dns_ttl = 30
dns_tsig_key_name = 'example_key_name'
dns_tsig_key_secret = 'aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1vSGc1U0pZUkhBMA=='
# Empty DNS keyring object to be populated later
dns_keyring = None

# HTTP server config
listen_host = '127.0.0.1'
listen_port = '8000'

# HTTPS config
ssl_enabled = False
ssl_key_file = '/etc/letsencrypt/live/example.com/privkey.pem'
ssl_cert_file = '/etc/letsencrypt/live/example.com/fullchain.pem'

# HTTP basic auth config
basic_auth_enabled = False
basic_auth_user = 'user'
basic_auth_pass = 'pass'

log_format = colorlog.ColoredFormatter(
        '%(asctime)s %(log_color)s[%(levelname)s]%(reset)s %(name)s: %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
            }
        )

handler = colorlog.StreamHandler()
handler.setFormatter(log_format)
logger = colorlog.getLogger('dnsupdate')
logger.addHandler(handler)
logging_level = logging.getLevelName(os.environ.get('log_level', log_level))
logger.setLevel(logging_level)

resolver = dns.resolver.Resolver(configure=False)

def GetCurrentIP(fqdn):
    # Get what's currently in DNS
    curent_ip = None
    logger.debug('Querying IP for ' + str(fqdn) + ' from ' + str(dns_nameserver))
    try:
        answer = resolver.query(fqdn, 'A')
        current_ip = answer[0].to_text()
        logger.debug('Got current IP: ' + str(current_ip))
    except (dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            KeyError):
        # If it's not in DNS, return nothing
        logger.debug('No IP in DNS for ' + str(current_ip))
        current_ip = None

    return current_ip


def UpdateDNS(fqdn, new_ip):
    logger.debug('Doing DNS update for ' + fqdn)
    logger.debug('New IP: ' + new_ip)

    update = dns.update.Update(dns_zone, keyring=dns_keyring)

    logger.debug('Updating record for ' + fqdn)
    update.replace(fqdn, dns_ttl, 'A', new_ip)

    try:
        response = dns.query.tcp(update, dns_nameserver, timeout=10)
        logger.info('Update done')
        dns_resp = 'good ' + str(new_ip)
        return dns_resp
    except dns.tsig.PeerBadKey:
        logger.error('TSIG key failure on update!')
        # If our tsig key is broken, return 'badagent'
        # even though this is not technically correct
        # it should stop inadyn from trying repeatedly
        dns_resp = 'badagent'
        return dns_resp
    # We should not get here
    # If we do, something is very wrong
    dns_resp = '911'
    return dns_resp


def ProcessReq(request_query, remote_ip):
    # To do:
    # Multiple domain updates as per https://www.noip.com/integrate/request
    try:
        fqdn = request_query['hostname']
        # Add a '.' to the end of the hostname if not present
        # so this represents a 'full' DNS name
        if not fqdn.endswith('.'):
            fqdn += '.'
    except KeyError:
        fqdn = None

    # To do:
    # Detect IPv6 address in myip as per https://www.noip.com/integrate/request
    if 'myip' in request_query:
        new_ip = request_query['myip']
    # If there's no ip specified, we should use the client IP
    else:
        new_ip = remote_ip
    # Not used by UDM yet(?) but specified in https://www.noip.com/integrate/request
    # if 'myipv6' in request_query:
    #     new_ipv6 = request_query['myipv6']
    # if 'offline' in request_query:
    #     offline = True
    return fqdn, new_ip


async def UpdateReq(request):
    logger.info('Update request from ' + str(request.remote))
    fqdn, new_ip = ProcessReq(request.query, request.remote)
    # Check the FQDN
    if not fqdn:
        logger.error('No FQDN in request')
        return web.Response(text='nohost')

    if not fqdn.endswith(dns_zone):
        logger.error('FQDN is not in DNS zone specified')
        return web.Response(text='nohost')

    logger.info(fqdn)

    # Get the current IP from DNS
    logger.debug('Getting current IP')
    current_ip = GetCurrentIP(fqdn)

    # Check the new IP supplied is valid
    try:
        socket.inet_aton(new_ip)
    except socket.error:
        logger.error('Invalid new IP in request: ' + str(new_ip))
        return web.Response(text='nochg ' + str(current_ip))

    logger.info(new_ip)

    # Check if we actually need to update
    if new_ip == current_ip:
        logger.info('New IP matches current IP, no update required')
        return web.Response(text='nochg ' + str(current_ip))

    dns_resp = UpdateDNS(fqdn, new_ip)
    return web.Response(text=dns_resp)

def build_conf():

    global dns_nameserver
    global dns_zone
    global dns_ttl
    global dns_tsig_key_name
    global dns_tsig_key_secret
    global listen_host
    global listen_port
    global ssl_enabled
    global ssl_key_file
    global ssl_cert_file
    global basic_auth_enabled
    global basic_auth_user
    global basic_auth_pass

    # Update config from environment variables if present
    dns_nameserver = os.environ.get('dns_nameserver', dns_nameserver)
    dns_zone = os.environ.get('dns_zone', dns_zone)
    dns_ttl = os.environ.get('dns_ttl', dns_ttl)
    dns_tsig_key_name = os.environ.get('dns_tsig_key_name', dns_tsig_key_name)
    dns_tsig_key_secret = os.environ.get('dns_tsig_key_secret', dns_tsig_key_secret)
    listen_host = os.environ.get('listen_host', listen_host)
    listen_port = os.environ.get('listen_port', listen_port)
    ssl_enabled = bool(strtobool(os.environ.get('ssl_enabled'))) if os.environ.get('ssl_enabled') else ssl_enabled
    ssl_key_file = os.environ.get('ssl_key_file', ssl_key_file)
    ssl_cert_file = os.environ.get('ssl_cert_file', ssl_cert_file)
    basic_auth_enabled = bool(strtobool(os.environ.get('basic_auth_enabled'))) if os.environ.get('basic_auth_enabled') else basic_auth_enabled
    basic_auth_user = os.environ.get('basic_auth_user', basic_auth_user)
    basic_auth_pass = os.environ.get('basic_auth_pass', basic_auth_pass)

    # Print config for troubleshooting
    logger.debug('dns_nameserver = ' + dns_nameserver)
    logger.debug('dns_zone = ' + dns_zone)
    logger.debug('dns_ttl = ' + str(dns_ttl))
    logger.debug('dns_tsig_key_name = ' + dns_tsig_key_name)
    logger.debug('dns_tsig_key_secret = ***********')
    logger.debug('listen_host = ' + listen_host)
    logger.debug('listen_port = ' + listen_port)
    logger.debug('ssl_enabled = ' + str(ssl_enabled))
    logger.debug('ssl_key_file = ' + ssl_key_file)
    logger.debug('ssl_cert_file = ' + ssl_cert_file)
    logger.debug('basic_auth_enabled = ' + str(basic_auth_enabled))
    logger.debug('basic_auth_user = ' + basic_auth_user)
    logger.debug('basic_auth_pass = ' + basic_auth_pass)

def main():

    logger.info('Starting noip-rfc2136')

    # Build the configuration from environment variables or globals
    build_conf()

    # Set name servers
    resolver.nameservers = [dns_nameserver]

    # Load our TSIG key
    dns_update_key = {}
    dns_update_key[dns_tsig_key_name] = dns_tsig_key_secret
    global dns_keyring
    dns_keyring = dns.tsigkeyring.from_text(dns_update_key)
    logger.debug('Loaded TSIG key ' + dns_tsig_key_name + ' from config')

    # Load our SSL key
    if ssl_enabled:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(ssl_cert_file, ssl_key_file)
        logger.debug('Loaded SSL key: ' + str(ssl_key_file))
        logger.debug('Loaded SSL certificate: ' + str(ssl_cert_file))
    else:
        context = None

    app = web.Application()
    app.add_routes([web.get('/update', UpdateReq)])
    if basic_auth_enabled:
        app.middlewares.append(
            basic_auth_middleware(
                ('/',),
                {basic_auth_user: basic_auth_pass},
            )
        )
    web.run_app(app, host=listen_host, port=listen_port, ssl_context=context)


if __name__ == '__main__':
    main()
