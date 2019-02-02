from typing import List

from .catlog_db import CatlogDb


def add_domain(catlog_db: CatlogDb, args):
    if len(args) != 1:
        raise Exception("config add-domain command expects exactly one argument")
    catlog_db.add_domain(args[0])


def disable_domain(catlog_db: CatlogDb, args):
    if len(args) != 1:
        raise Exception("config add-domain command expects exactly one argument")
    catlog_db.disable_domain(args[0])


def get_domains(catlog_db: CatlogDb, args):
    if len(args) != 0:
        raise Exception("config get-domains command expects no arguments")
    domains = catlog_db.get_domains()

    domain_col_width = len("domain")
    for domain in domains:
        domain_col_width = max(domain_col_width, len(domain))

    print("domain{}\tprod\tstaging".format(" " * (domain_col_width - len("domain"))))
    for domain in domains:
        prod, staging = domains[domain]
        print("{}{}\t{}\t{}".format(domain, " " * (domain_col_width - len(domain)), prod, staging))


def config_cmd(catlog_db: CatlogDb, args: List[str]):
    if len(args) <= 0:
        raise Exception("No subcommand found for config")

    subcommand = args[0]
    if subcommand == "add-domain":
        add_domain(catlog_db, args[1:])
    elif subcommand == "disable-domain":
        disable_domain(catlog_db, args[1:])
    elif subcommand == "get-domains":
        get_domains(catlog_db, args[1:])
    else:
        raise Exception("Unsupported config subcommand: " + subcommand)
