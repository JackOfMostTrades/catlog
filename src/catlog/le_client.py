import hashlib
from typing import List, Tuple

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
from zope.interface import implementer

from . import cert_encoding
from .catlog_db import CatlogDb, Domain
from .cert_encoding import data_to_domains, pem_to_der
from .dns_provider import CatlogResolver


@implementer(certbot.interfaces.IConfig)
class SimpleConfig:
    def __init__(self, staging: bool):
        if staging:
            self.server = certbot.constants.STAGING_URI
        else:
            self.server = certbot.constants.CLI_DEFAULTS["server"]

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
        self.eab_hmac_key = None
        self.eab_kid = None
        self.config_dir = None


class SimpleAccountStorage(certbot.interfaces.AccountStorage):
    def __init__(self, staging: bool, catlog_db: CatlogDb):
        self._staging = staging
        self._db = catlog_db

    def find_all(self) -> List[certbot.account.Account]:
        accounts = []
        for row in self._db.find_all_accounts(self._staging):
            accounts.append(certbot.account.Account(
                acme.messages.RegistrationResource.json_loads(row[1]),
                jose.JWK.json_loads(row[2])))
        return accounts

    def load(self, account_id: str) -> certbot.account.Account:
        account_row = self._db.load_account(self._staging, account_id)
        if account_row is None:
            raise certbot.errors.AccountNotFound("Could not find account id " + account_id)
        return certbot.account.Account(
            acme.messages.RegistrationResource.json_loads(account_row[1]),
            jose.JWK.json_loads(account_row[2]))

    def save(self, account: certbot.account.Account, client) -> None:
        self._db.save_account(self._staging,
                              account.id,
                              account.regr.json_dumps(),
                              account.key.json_dumps())


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
    def __init__(self, staging: bool, catlog_db: CatlogDb):
        self._staging = staging
        self._catlog_db = catlog_db
        self._config = SimpleConfig(staging)
        zope.component.getGlobalSiteManager().registerUtility(self._config, certbot.interfaces.IConfig)
        zope.component.getGlobalSiteManager().registerUtility(certbot.display.util.NoninteractiveDisplay("/dev/null"),
                                                              certbot.interfaces.IDisplay)
        zope.component.getGlobalSiteManager().registerUtility(certbot.reporter.Reporter(self._config),
                                                              certbot.interfaces.IReporter)

    def _mint_cert_with_domains(self, domains: List[str]) -> Tuple[bytes, bytes]:
        account_storage = SimpleAccountStorage(self._staging, self._catlog_db)
        if len(account_storage.find_all()) == 0:
            certbot.client.register(self._config, account_storage, tos_cb=None)
        account = account_storage.find_all()[0]
        catlog_resolver = CatlogResolver()
        catlog_resolver.start()
        try:
            authenticator = SimpleAuthenticator(catlog_resolver)
            installer = NoopInstaller()
            client = certbot.client.Client(self._config, account, authenticator, installer, acme=None)
            result = client.obtain_certificate(domains)

            # Convert the result to DER bytes
            cert, issuer = (pem_to_der(result[0]), pem_to_der(result[1]))

            return (cert, issuer)
        finally:
            catlog_resolver.stop()

    def mint_cert(self, domain: Domain, common_name: str, raw_data: bytes) -> Tuple[bytes, bytes]:
        cert, issuer = self._mint_cert_with_domains(data_to_domains(raw_data, common_name, domain.domain))
        leaf_hashes = cert_encoding.cert_to_leaf_hashes(cert, issuer)
        # Log the certificate
        self._catlog_db.add_certificate_log(domain, hashlib.sha256(cert).digest(), self._staging, leaf_hashes)
        return (cert, issuer)
