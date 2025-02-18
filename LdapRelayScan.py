import urllib.parse
import dns.resolver
import ldap3
import argparse
import sys
import ssl
import socket
import getpass
import asyncio
from msldap.connection import MSLDAPClientConnection
from msldap.commons.factory import LDAPConnectionFactory


class CheckLdaps:
    def __init__(self, nameserver, username, cmdLineOptions):
        self.options = cmdLineOptions
        self.__nameserver = nameserver
        self.__username = username

# Conduct a bind to LDAPS and determine if channel
# binding is enforced based on the contents of potential
# errors returned. This can be determined unauthenticated,
# because the error indicating channel binding enforcement
# will be returned regardless of a successful LDAPS bind.
def run_ldaps_noEPA(inputUser, inputPassword, dcTarget):
    try:
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
        ldapServer = ldap3.Server(
            dcTarget, use_ssl=True, port=636, get_info=ldap3.ALL, tls=tls)
        ldapConn = ldap3.Connection(
            ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM)
        if not ldapConn.bind():
            if "data 80090346" in str(ldapConn.result):
                return True  # channel binding IS enforced
            elif "data 52e" in str(ldapConn.result):
                return False  # channel binding not enforced
            else:
                print("UNEXPECTED ERROR: " + str(ldapConn.result))
        else:
            # LDAPS bind successful
            return False  # because channel binding is not enforced
    except Exception as e:
        print("\n   [!] " + dcTarget + " -", str(e))
        print("        * Ensure DNS is resolving properly, and that you can reach LDAPS on this host")

# Conduct a bind to LDAPS with channel binding supported
# but intentionally miscalculated. In the case that an
# LDAPS bind has occurred without channel binding supported,
# you can determine whether the policy is set to "never" or
# if it's set to "when supported" based on the potential
# error received from the bind attempt.
async def run_ldaps_withEPA(inputUser, inputPassword, dcTarget, fqdn, timeout):
    try:
        inputPassword = urllib.parse.quote(inputPassword)
        url = 'ldaps+ntlm-password://' + inputUser + ':' + inputPassword + '@' + dcTarget
        conn_url = LDAPConnectionFactory.from_url(url)
        ldaps_client = conn_url.get_client()
        ldaps_client.target.timeout = timeout
        ldapsClientConn = MSLDAPClientConnection(ldaps_client.target, ldaps_client.creds)
        _, err = await ldapsClientConn.connect()
        if err is not None:
            raise err
        # Forcing a miscalculation of the "Channel Bindings" av pair in Type 3 NTLM message
        ldapsClientConn.cb_data = b'\x00' * 64  # simplified version
        _, err = await ldapsClientConn.bind()
        if "data 80090346" in str(err):
            return True
        elif "data 52e" in str(err):
            return False
        elif err is not None:
            print("ERROR while connecting to " + dcTarget + ": " + str(err))
        elif err is None:
            return False
    except Exception as e:
        print("something went wrong during ldaps_withEPA bind:" + str(e))


# DNS query of an SRV record that should return
# a list of domain controllers.
def ResolveDCs(nameserverIp, fqdn):
    dcList = []
    DnsResolver = dns.resolver.Resolver()
    DnsResolver.timeout = 20
    DnsResolver.nameservers = [nameserverIp]
    dcQuery = DnsResolver.resolve("_ldap._tcp.dc._msdcs." + fqdn, 'SRV', tcp=True)
    testout = str(dcQuery.response).split("\n")
    for line in testout:
        if "IN A" in line:
            dcList.append(line.split(" ")[0].rstrip(line.split(" ")[0][-1]))
    return dcList

# Conduct an anonymous bind to the provided "nameserver"
# argument during execution. This should work even if LDAP
# server integrity checks are enforced. The FQDN of the
# internal domain will be parsed from the basic server
# info gathered from that anonymous bind.
def InternalDomainFromAnonymousLdap(nameserverIp):
    tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
    ldapServer = ldap3.Server(
        nameserverIp, use_ssl=False, port=389, get_info=ldap3.ALL)
    ldapConn = ldap3.Connection(ldapServer, authentication=ldap3.ANONYMOUS)
    ldapConn.bind()
    parsedServerInfo = str(ldapServer.info).split("\n")
    fqdn = ""
    for line in parsedServerInfo:
        if "$" in line:
            fqdn = line.strip().split("@")[1]
    return fqdn


# Domain Controllers do not have a certificate setup for
# LDAPS on port 636 by default. If this has not been setup,
# the TLS handshake will hang and you will not be able to 
# interact with LDAPS. The condition for the certificate
# existing as it should is either an error regarding 
# the fact that the certificate is self-signed, or
# no error at all. Any other "successful" edge cases
# not yet accounted for.
def DoesLdapsCompleteHandshake(dcIp):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_OPTIONAL
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
#    ssl_sock = ssl.wrap_socket(s,
#                               cert_reqs=ssl.CERT_OPTIONAL,
#                               suppress_ragged_eofs=False,
#                               do_handshake_on_connect=False)
    ssl_sock = context.wrap_socket(s, server_hostname=dcIp, do_handshake_on_connect=False)
    ssl_sock.connect((dcIp, 636))
    try:
        ssl_sock.do_handshake()
        ssl_sock.close()
        return True
    except ssl.SSLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            ssl_sock.close()
            return True
        if "handshake operation timed out" in str(e):
            ssl_sock.close()
            return False
        else:
            print("Unexpected error during LDAPS handshake: " + str(e))
        ssl_sock.close()

# Conduct an LDAP bind and determine if server signing
# requirements are enforced based on potential errors
# during the bind attempt.
def run_ldap(inputUser, inputPassword, dcTarget):
    ldapServer = ldap3.Server(
        dcTarget, use_ssl=False, port=389, get_info=ldap3.ALL)
    ldapConn = ldap3.Connection(
        ldapServer, user=inputUser, password=inputPassword, authentication=ldap3.NTLM)
    if not ldapConn.bind():
        ldapConn_result_str = str(ldapConn.result)
        if "stronger" in ldapConn_result_str:
            return True  # LDAP server signing requirements ARE enforced
        elif "data 52e" in ldapConn_result_str or "data 532" in ldapConn_result_str:
            print("[!!!] invalid credentials - aborting to prevent unnecessary authentication")
            exit()
        else:
            print("UNEXPECTED ERROR: " + ldapConn_result_str)
    else:
        # LDAP bind successful
        return False  # LDAP server signing requirements are not enforced

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Checks Domain Controllers for LDAP authentication protection. "
                    "You can check for only LDAPS protections (channel binding) -- done unauthenticated -- "
                    "or for both LDAPS and LDAP (server signing) protections (requires authentication)."
    )
    parser.add_argument('-method', choices=['LDAPS','BOTH'], default='LDAPS', metavar="method", action='store',
                        help="LDAPS or BOTH - LDAPS checks for channel binding, BOTH checks for LDAP signing and LDAP channel binding [authentication required]")
    parser.add_argument('-dc-ip', required=True, action='store',
                        help='DNS Nameserver on network. Any DC\'s IPv4 address should work.')
    parser.add_argument('-u', default='guest', metavar='username', action='store',
                        help='Username value (without the domain prefix).')
    parser.add_argument('-d', '--domain', metavar='domain', action='store',
                        help='Specify the domain for the user credentials. '
                             'If not provided, the domain will be auto-discovered from the provided DC.')
    parser.add_argument('-timeout', default=10, metavar='timeout', action='store', type=int,
                        help='The timeout for MSLDAP client connection.')
    parser.add_argument('-p', default='defaultpass', metavar='password', action='store',
                        help='User password.')
    parser.add_argument('-nthash', metavar='nthash', action='store',
                        help='NT hash of password')
    parser.add_argument('-target', metavar='target_dc', action='store',
                        help='Target a single Domain Controller (DC) instead of checking all discovered DCs')
    options = parser.parse_args()
    domainUser = options.u
    password = options.p

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    if options.dc_ip is None:
        print("-dc-ip is required")
        exit()
    if options.method == 'BOTH':
        if domainUser == 'guest':
            print("[i] Using BOTH method requires a username parameter")
            exit()
    if options.method == 'BOTH' and options.u != 'guest' and (options.p != 'defaultpass' or options.nthash is not None):
        if options.p == 'defaultpass' and options.nthash is not None:
            password = "aad3b435b51404eeaad3b435b51404ee:" + options.nthash
        elif options.p != 'defaultpass' and options.nthash is None:
            password = options.p
        else:
            print("Something incorrect while providing credential material options")
    if options.method == 'BOTH' and options.p == 'defaultpass' and options.nthash is None:   
        password = getpass.getpass(prompt="Password: ")

    # Determine the domain to use.
    # If -d/--domain is provided, use that value, otherwise, auto-discover it.
    if options.domain:
        domainUsed = options.domain
    else:
        domainUsed = InternalDomainFromAnonymousLdap(options.dc_ip)

    # If the user provided the '-target' switch, only check that DC.
    if options.target:
        dcList = [options.target]
        print("\n~Using single Domain Controller specified by -target~")
        print("   " + options.target)
    else:
        dcList = ResolveDCs(options.dc_ip, domainUsed)
        print("\n~Domain Controllers identified~")
        for dc in dcList:
            print("   " + dc)

    print("\n~Checking DCs for LDAP NTLM relay protections~")
    # Build the username using the determined domain and the provided username.
    username = domainUsed + "\\" + domainUser

    # For troubleshooting:
    # print("Authenticating with:\nUser: " + username + "\nPassword: " + password + "\nDomain used: " + domainUsed)

    for dc in dcList:
        print("   " + dc)
        try:
            if options.method == "BOTH":
                ldapIsProtected = run_ldap(username, password, dc)
                if ldapIsProtected == False:
                    print("      [+] (LDAP)  SERVER SIGNING REQUIREMENTS NOT ENFORCED! ")
                elif ldapIsProtected == True:
                    print("      [-] (LDAP)  server enforcing signing requirements")
            if DoesLdapsCompleteHandshake(dc) == True:
                ldapsChannelBindingAlwaysCheck = run_ldaps_noEPA(username, password, dc)
                ldapsChannelBindingWhenSupportedCheck = asyncio.run(run_ldaps_withEPA(username, password, dc, domainUsed, options.timeout))
                if ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == True:
                    print("      [-] (LDAPS) channel binding is set to \"when supported\" - this")
                    print("                  may prevent an NTLM relay depending on the client's")
                    print("                  support for channel binding.")
                elif ldapsChannelBindingAlwaysCheck == False and ldapsChannelBindingWhenSupportedCheck == False:
                    print("      [+] (LDAPS) CHANNEL BINDING SET TO \"NEVER\"! PARTY TIME!")
                elif ldapsChannelBindingAlwaysCheck == True:
                    print("      [-] (LDAPS) channel binding set to \"required\", no fun allowed")
                else:
                    print("\nSomething went wrong...")
                    print("For troubleshooting:\nldapsChannelBindingAlwaysCheck - " + str(ldapsChannelBindingAlwaysCheck) +
                          "\nldapsChannelBindingWhenSupportedCheck: " + str(ldapsChannelBindingWhenSupportedCheck))
                    exit()
            elif DoesLdapsCompleteHandshake(dc) == False:
                print("      [!] " + dc + " - cannot complete TLS handshake, cert likely not configured")
        except Exception as e:
            print("      [-] ERROR: " + str(e))
    print()
