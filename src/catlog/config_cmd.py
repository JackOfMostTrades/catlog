from .catlog_db import CatlogDb


def add_domain(args):
    if len(args) != 1:
        raise Exception("config add-domain command expects exactly one argument")
    catlog_db = CatlogDb()
    try:
        catlog_db.add_domain(args[0])
    finally:
        catlog_db.close()


def disable_domain(args):
    if len(args) != 1:
        raise Exception("config add-domain command expects exactly one argument")
    catlog_db = CatlogDb()
    try:
        catlog_db.disable_domain(args[0])
    finally:
        catlog_db.close()


def get_domains(args):
    if len(args) != 0:
        raise Exception("config get-domains command expects no arguments")
    catlog_db = CatlogDb()
    try:
        domains = catlog_db.get_domains()
    finally:
        catlog_db.close()

    domain_col_width = len("domain")
    for domain in domains:
        domain_col_width = max(domain_col_width, len(domain))

    print("domain{}\tprod\tstaging".format(" " * (domain_col_width - len("domain"))))
    for domain in domains:
        prod, staging = domains[domain]
        print("{}{}\t{}\t{}".format(domain, " " * (domain_col_width - len(domain)), prod, staging))


def config_cmd(args):
    if len(args) <= 0:
        raise Exception("No subcommand found for config")

    subcommand = args[0]
    if subcommand == "add-domain":
        add_domain(args[1:])
    elif subcommand == "disable-domain":
        disable_domain(args[1:])
    elif subcommand == "get-domains":
        get_domains(args[1:])
    else:
        raise Exception("Unsupported config subcommand: " + subcommand)
