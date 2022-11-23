#!/usr/bin/python3

import os
import sys
import ssl
import socket
import json
import logging
from time import sleep
from distutils.util import strtobool
import yaml
import colorlog
import dns.update
import dns.query
import dns.tsigkeyring
import dns.resolver
from aiohttp import web
from aiohttp_basicauth_middleware import basic_auth_middleware

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
logger = colorlog.getLogger('noip_rfc2136')
logger.addHandler(handler)
logger.setLevel("INFO")


# Config file
config = None
config_file = 'config.yaml'


class AppConfig:
    def __init__(self, file):
        self.file = file
        logger.info('Loading config from ' + self.file)
        if os.path.exists(self.file):
            with open(self.file, 'r') as file:
                logger.debug('Opened '+self.file)
                self.loaded_yaml = yaml.safe_load(file)
        else:
            logger.error("Error loading config: \'" + self.file + "\' not found")
            sys.exit(1)

        self.dns = self.Dns()
        self.dns.nameserver = self.loaded_yaml['noip_rfc2136']['dns']['nameserver']
        self.dns.zone = self.loaded_yaml['noip_rfc2136']['dns']['zone']
        if self.loaded_yaml['noip_rfc2136']['dns'].get("ttl") is not None:
            self.dns.ttl = self.loaded_yaml['noip_rfc2136']['dns']['ttl']
        if self.loaded_yaml['noip_rfc2136']['dns'].get("create_enabled") is not None:
            self.dns.create_enabled = self.loaded_yaml['noip_rfc2136']['dns']['create_enabled']
        self.dns.tsig_key_name = self.loaded_yaml['noip_rfc2136']['dns']['tsig_key_name']
        self.dns.tsig_key_secret = self.loaded_yaml['noip_rfc2136']['dns']['tsig_key_secret']
        self.dns.tsig_key_algorithm = self.loaded_yaml['noip_rfc2136']['dns']['tsig_key_algorithm']

        self.listen = self.Listen()
        if self.loaded_yaml['noip_rfc2136'].get("listen") is not None:
            if self.loaded_yaml['noip_rfc2136']['listen'].get("host") is not None:
                self.listen.host = self.loaded_yaml['noip_rfc2136']['listen']['host']
            if self.loaded_yaml['noip_rfc2136']['listen'].get("port") is not None:
                self.listen.port = self.loaded_yaml['noip_rfc2136']['listen']['port']

        self.https = self.Https()
        if self.loaded_yaml['noip_rfc2136'].get("https") is not None:
            if self.loaded_yaml['noip_rfc2136']['https'].get("enabled") is not None:
                self.https.enabled = self.loaded_yaml['noip_rfc2136']['https']['enabled']
            if self.https.enabled:
                self.https.key_file = self.loaded_yaml['noip_rfc2136']['https']['key_file']
                self.https.cert_file = self.loaded_yaml['noip_rfc2136']['https']['cert_file']

        self.auth = self.Auth()
        if self.loaded_yaml['noip_rfc2136'].get("auth") is not None:
            if self.loaded_yaml['noip_rfc2136']['auth'].get("enabled") is not None:
                self.auth.enabled = self.loaded_yaml['noip_rfc2136']['auth']['enabled']
            if self.auth.enabled:
                self.auth.username = self.loaded_yaml['noip_rfc2136']['auth']['username']
                self.auth.password = self.loaded_yaml['noip_rfc2136']['auth']['password']

        self.log = self.Log()
        if self.loaded_yaml['noip_rfc2136'].get("log") is not None:
            if self.loaded_yaml['noip_rfc2136']['log'].get("level") is not None:
                self.log.level = self.loaded_yaml['noip_rfc2136']['log']['level']

    class Dns:
        def __init__(self):
            self.nameserver = None
            self.zone = None
            self.ttl = 30
            self.create_enabled = False
            self.key_name = None
            self.key_secret = None
            self.key_algorithm = None

    class Listen:
        def __init__(self):
            self.host = 'localhost'
            self.port = 8000

    class Https:
        def __init__(self):
            self.enabled = False
            self.key_file = None
            self.cert_file = None

    class Auth:
        def __init__(self):
            self.enabled = False
            self.username = None
            self.password = None

    class Log:
        def __init__(self):
            self.level = "INFO"

# Empty DNS keyring object to be populated later
dns_keyring = None
resolver = dns.resolver.Resolver(configure=False)

def GetCurrentIP(fqdn):

    global config

    # Get what's currently in DNS
    curent_ip = None
    logger.debug('Querying IP for ' + str(fqdn) + ' from ' + str(config.dns.nameserver))
    try:
        answer = resolver.resolve(fqdn, 'A')
        current_ip = answer[0].to_text()
        status = 'OK'
        logger.debug('Got current IP: ' + str(current_ip))
    except (dns.resolver.NXDOMAIN,
            KeyError):
        # If it's not in DNS, return nothing
        logger.debug('No IP in DNS for ' + str(fqdn))
        current_ip = None
        status = 'MISSING'
    except (dns.resolver.NoAnswer,
            dns.resolver.NoNameservers):
        logger.warning('No response from DNS for ' + str(fqdn))
        current_ip = None
        status = 'MISCONFIGURED_DNS'
    return current_ip, status


def UpdateDNS(fqdn, new_ip):
    logger.debug('Doing DNS update for ' + fqdn)
    logger.debug('New IP: ' + new_ip)

    update = dns.update.Update(config.dns.zone, keyring=dns_keyring, keyalgorithm=config.dns.tsig_key_algorithm)

    logger.debug('Updating record for ' + fqdn)
    update.replace(fqdn, config.dns.ttl, 'A', new_ip)

    try:
        response = dns.query.tcp(update, config.dns.nameserver, timeout=10)
        logger.info('Update done')
        dns_resp = 'good ' + str(new_ip)
        return dns_resp
    except (dns.tsig.PeerBadKey,
            dns.tsig.BadSignature,
            dns.tsig.BadTime):
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

    global config

    logger.info('Update request from ' + str(request.remote))
    fqdn, new_ip = ProcessReq(request.query, request.remote)
    # Check the FQDN
    if not fqdn:
        logger.error('No FQDN in request')
        return web.Response(text='nohost')

    if not fqdn == config.dns.zone and not fqdn.endswith("." + config.dns.zone):
        logger.error('FQDN is not in DNS zone specified')
        return web.Response(text='nohost')

    logger.info("Zone: " + str(fqdn))

    # Get the current IP from DNS
    logger.debug('Getting current IP')
    current_ip,status = GetCurrentIP(fqdn)

    if status == 'MISCONFIGURED_DNS':
        logger.error('Cannot update ' + str(fqdn) + ' in zone ' + str(config.dns.zone))
        return web.Response(text='badagent')

    # FQDN does not exist
    if status == 'MISSING':
        logger.warning("No DNS record for " + str(fqdn))
        # Check if we're configured to create records
        if config.dns.create_enabled:
            logger.warning('Creating record for ' + str(fqdn))
            status = 'OK'
        else:
            logger.error('FQDN does not exist and record creation is disabled!')
            # Return 'nohost'
            return web.Response(text='nohost')

    if status == 'OK':
        # Check the new IP supplied is valid
        try:
            socket.inet_aton(new_ip)
            logger.info("New IP: " + new_ip)
        except socket.error:
            logger.error('Invalid new IP in request: ' + str(new_ip))
            return web.Response(text='nochg ' + str(current_ip))

        # Check if we actually need to update
        if new_ip != current_ip:
            dns_resp = UpdateDNS(fqdn, new_ip)
            return web.Response(text=dns_resp)
        else:
            logger.info('New IP matches current IP, no update required')
            return web.Response(text='nochg ' + str(current_ip))
    # We should not get here
    # If we do, something is very wrong
    dns_resp = '911'
    return web.Response(text=dns_resp)


def build_conf(config_file):

    config = AppConfig(config_file)
    # Update config from environment variables if present
    config.dns.nameserver = socket.gethostbyname(os.environ.get('NOIP_RFC2136_DNS_NAMESERVER', config.dns.nameserver))
    config.dns.zone = os.environ.get('NOIP_RFC2136_DNS_ZONE', config.dns.zone)
    config.dns.ttl = os.environ.get('NOIP_RFC2136_DNS_TTL', config.dns.ttl)
    config.dns.create_enabled = os.environ.get('NOIP_RFC2136_DNS_CREATE_ENABLED', config.dns.create_enabled)
    config.dns.tsig_key_name = os.environ.get('NOIP_RFC2136_DNS_TSIG_KEY_NAME', config.dns.tsig_key_name)
    config.dns.tsig_key_secret = os.environ.get('NOIP_RFC2136_DNS_TSIG_KEY_SECRET', config.dns.tsig_key_secret)
    config.dns.tsig_key_algorithm = os.environ.get('NOIP_RFC2136_DNS_TSIG_KEY_ALGORITHM', config.dns.tsig_key_algorithm)
    config.listen.host = os.environ.get('NOIP_RFC2136_LISTEN_HOST', config.listen.host)
    config.listen.port = os.environ.get('NOIP_RFC2136_LISTEN_PORT', config.listen.port)
    config.https.enabled = bool(strtobool(os.environ.get('NOIP_RFC2136_HTTPS_ENABLED'))) if os.environ.get('NOIP_RFC2136_HTTPS_ENABLED') else config.https.enabled
    if config.https.enabled:
        config.https.key_file = os.environ.get('NOIP_RFC2136_HTTPS_KEY_FILE', config.https.key_file)
        config.https.cert_file = os.environ.get('NOIP_RFC2136_HTTPS_CERT_FILE', config.https.cert_file)
    else:
        config.https.key_file = None
        config.https.cert_file = None
    config.auth.enabled = bool(strtobool(os.environ.get('NOIP_RFC2136_AUTH_ENABLED'))) if os.environ.get('NOIP_RFC2136_AUTH_ENABLED') else config.auth.enabled
    if config.auth.enabled:
        config.auth.username = os.environ.get('NOIP_RFC2136_AUTH_USERNAME', config.auth.username)
        config.auth.password = os.environ.get('NOIP_RFC2136_AUTH_PASSWORD', config.auth.password)
    else:
        config.auth.username = None
        config.auth.password = None

    config.log.level = logging.getLevelName(os.environ.get('NOIP_RFC2136_LOG_LEVEL', config.log.level))
    logger.setLevel(config.log.level)

    # Print config for troubleshooting
    logger.debug('config.dns.nameserver = ' + str(config.dns.nameserver))
    logger.debug('config.dns.zone = ' + str(config.dns.zone))
    logger.debug('config.dns.ttl = ' + str(config.dns.ttl))
    logger.debug('config.dns.create_enabled = ' + str(config.dns.create_enabled))
    logger.debug('config.dns.tsig_key_name = ' + str(config.dns.tsig_key_name))
    logger.debug('config.dns.tsig_key_secret = ***********')
    logger.debug('config.dns.tsig_key_algorithm = ' + str(config.dns.tsig_key_algorithm))
    logger.debug('config.listen.host = ' + str(config.listen.host))
    logger.debug('config.listen.port = ' + str(config.listen.port))
    logger.debug('config.https.enabled = ' + str(config.https.enabled))
    logger.debug('config.https.key_file = ' + str(config.https.key_file or 'None'))
    logger.debug('config.https.cert_file = ' + str(config.https.cert_file or 'None'))
    logger.debug('config.auth.enabled = ' + str(config.auth.enabled))
    logger.debug('config.auth.username = ' + str(config.auth.username or 'None'))
    logger.debug('config.auth.password = ' + str(config.auth.password or 'None'))

    return config


def main():

    global config

    logger.info('Starting noip-rfc2136')

    # Build the configuration from YAML file and environment variables if present
    config = build_conf(config_file)

    # Set name servers
    resolver.nameservers = [config.dns.nameserver]

    # Load our TSIG key
    dns_update_key = {}
    dns_update_key[config.dns.tsig_key_name] = config.dns.tsig_key_secret
    global dns_keyring
    dns_keyring = dns.tsigkeyring.from_text(dns_update_key)
    logger.debug('Loaded TSIG key ' + config.dns.tsig_key_name + ' from config')

    # Load our SSL key
    if config.https.enabled:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config.https.cert_file, config.https.key_file)
        logger.debug('Loaded SSL key: ' + str(config.https.key_file))
        logger.debug('Loaded SSL certificate: ' + str(config.https.cert_file))
    else:
        context = None

    app = web.Application()
    app.add_routes([web.get('/update', UpdateReq)])
    app.add_routes([web.get('/nic/update', UpdateReq)])
    if config.auth.enabled:
        app.middlewares.append(
            basic_auth_middleware(
                ('/',),
                {config.auth.username: config.auth.password},
            )
        )
    web.run_app(app, host=config.listen.host, port=config.listen.port, ssl_context=context)


if __name__ == '__main__':
    main()
