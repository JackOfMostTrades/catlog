import acme.challenges
import acme.messages
import certbot.account
import certbot.client
import certbot.constants
import certbot.display.util
import certbot.interfaces
import certbot.reporter
import zope.component
from zope.interface import implementer

from .cert_encoding import data_to_domains
from .dns_provider import CatlogResolver


@implementer(certbot.interfaces.IConfig)
class SimpleConfig:
    def __init__(self):
        self.server = certbot.constants.STAGING_URI

        self.user_agent = "CertbotACMEClient"
        self.rsa_key_size = 2048
        self.no_verify_ssl = False
        self.dry_run = True
        self.email = None
        self.eff_email = None
        self.pref_challs = None
        self.must_staple = False
        self.allow_subset_of_names = False
        self.register_unsafely_without_email = True
        self.debug_challenges = False


class SimpleAccountStorage(certbot.interfaces.AccountStorage):
    def __init__(self):
        self.account = None

    def find_all(self):
        if self.account is None:
            return []
        return [self.account]

    def load(self, account_id):
        if self.account is None or self.account.id != account_id:
            raise certbot.interfaces.AccountNotFound("Could not find account id " + account_id)
        return self.account

    def save(self, account, client):
        self.account = account


@implementer(certbot.interfaces.IAuthenticator)
class SimpleAuthenticator:

    def __init__(self, catlog_resolver):
        self._catlog_resolver = catlog_resolver

    def get_chall_pref(self, domain):
        return [acme.challenges.DNS01]

    def perform(self, achalls):
        responses = []
        for achall in achalls:
            # if type(achall) is not acme.challenges.DNS01:
            #    raise Exception("All challanges must be DNS01")
            result = achall.response_and_validation()
            responses.append(result[0])
            verification = result[1]
            domain = achall.validation_domain_name(achall.domain)
            # FIXME: Set txt record
            print(domain)
            print(verification)
            self._catlog_resolver.setTxt(domain, verification)
        return responses

    def cleanup(self, achalls):
        for achall in achalls:
            domain = achall.validation_domain_name(achall.domain)
            self._catlog_resolver.clearTxt(domain)


@implementer(certbot.interfaces.IInstaller)
class NoopInstaller:
    pass


def mint_cert(raw_data, dns_suffix):
    config = SimpleConfig()
    zope.component.getGlobalSiteManager().registerUtility(config, certbot.interfaces.IConfig)
    zope.component.getGlobalSiteManager().registerUtility(certbot.display.util.NoninteractiveDisplay("/dev/null"),
                                                          certbot.interfaces.IDisplay)
    zope.component.getGlobalSiteManager().registerUtility(certbot.reporter.Reporter(config),
                                                          certbot.interfaces.IReporter)
    account_storage = SimpleAccountStorage()
    if len(account_storage.find_all()) == 0:
        certbot.client.register(config, account_storage, tos_cb=None)
    account = account_storage.find_all()[0]
    catlog_resolver = CatlogResolver()
    catlog_resolver.start()
    try:
        authenticator = SimpleAuthenticator(catlog_resolver)
        installer = NoopInstaller()
        client = certbot.client.Client(config, account, authenticator, installer, acme=None)

        result = client.obtain_certificate(data_to_domains(raw_data, dns_suffix))
        return (result[0], result[1])  # cert as a pem string and issuer as pem string
    finally:
        catlog_resolver.stop()
