import hashlib
from typing import List

import acme.challenges
import acme.messages
import certbot.account
import certbot.client
import certbot.constants
import certbot.display.util
import certbot.errors
import certbot.interfaces
import certbot.reporter
import josepy as jose
import zope.component
from asn1crypto import pem
from zope.interface import implementer

from . import catlog_db
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
    def __init__(self, catlogDb: catlog_db.CatlogDb):
        self._db = catlogDb

    def find_all(self) -> List[certbot.account.Account]:
        accounts = []
        for row in self._db.find_all_accounts():
            accounts.append(certbot.account.Account(
                acme.messages.RegistrationResource.json_loads(row[1]),
                jose.JWK.json_loads(row[2])))
        return accounts

    def load(self, account_id: str) -> certbot.account.Account:
        account_row = self._db.load_account(account_id)
        if account_row is None:
            raise certbot.errors.AccountNotFound("Could not find account id " + account_id)
        return certbot.account.Account(
            acme.messages.RegistrationResource.json_loads(account_row[1]),
            jose.JWK.json_loads(account_row[2]))

    def save(self, account: certbot.account.Account, client) -> None:
        self._db.save_account(account.id,
                              account.regr.to_json(),
                              account.key.to_json())


@implementer(certbot.interfaces.IAuthenticator)
class SimpleAuthenticator:

    def __init__(self, catlog_resolver: CatlogResolver):
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


class LeClient:
    def __init__(self, catlogDb: catlog_db.CatlogDb):
        self._catlogDb = catlogDb
        self._config = SimpleConfig()
        zope.component.getGlobalSiteManager().registerUtility(self._config, certbot.interfaces.IConfig)
        zope.component.getGlobalSiteManager().registerUtility(certbot.display.util.NoninteractiveDisplay("/dev/null"),
                                                              certbot.interfaces.IDisplay)
        zope.component.getGlobalSiteManager().registerUtility(certbot.reporter.Reporter(self._config),
                                                              certbot.interfaces.IReporter)

    def mint_cert(self, raw_data: bytes):
        domain = self._catlogDb.pick_domain(True)
        account_storage = SimpleAccountStorage(self._catlogDb)
        if len(account_storage.find_all()) == 0:
            certbot.client.register(self._config, account_storage, tos_cb=None)
        account = account_storage.find_all()[0]
        catlog_resolver = CatlogResolver()
        catlog_resolver.start()
        try:
            authenticator = SimpleAuthenticator(catlog_resolver)
            installer = NoopInstaller()
            client = certbot.client.Client(self._config, account, authenticator, installer, acme=None)
            result = client.obtain_certificate(data_to_domains(raw_data, domain.domain))

            # Log the certificate
            if not pem.detect(result[0]):
                raise Exception("Unable to parse PEM result of obtained cert: " + result[0])
            _, _, der_bytes = pem.unarmor(result[0])
            self._catlogDb.add_certificate_log(domain, hashlib.sha256(der_bytes).digest(), True)

            return (result[0], result[1])  # cert as a pem string and issuer as pem string
        finally:
            catlog_resolver.stop()
