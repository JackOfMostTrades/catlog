CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER NOT NULL PRIMARY KEY,
  account_id VARCHAR(255) NOT NULL,
  registration_json TEXT NOT NULL,
  key_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS accounts_account_id_idx ON accounts (account_id);

CREATE TABLE IF NOT EXISTS domains (
  id INTEGER NOT NULL PRIMARY KEY,
  -- The domain under which certs will be minted. E.g. foo.mytld.com
  domain VARCHAR(255) NOT NULL,
  -- The TLD for this domain against which rate limits will count. Generally this will be
  -- the same as `domain`, but this might not be the case if you want to put all certs under
  -- foo.mytld.com and bar.mytld.com, but both of these would count against the `mytld.com`
  -- rate limit
  tld VARCHAR(255) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS domains_domain_idx ON domains (domain);

CREATE TABLE IF NOT EXISTS certificate_log (
  id INTEGER NOT NULL PRIMARY KEY,
  date INTEGER NOT NULL, -- Epoch time in seconds
  domain_id INTEGER NOT NULL, -- Domain the cert was created under.
  fingerprint_sha256 TEXT NOT NULL, -- SHA-256 fingerprint of the cert
  staging INTEGER NOT NULL, -- Boolean value indicating if cert was created in a "staging" env.
  FOREIGN KEY (domain_id) REFERENCES domains(id)
);

CREATE TABLE IF NOT EXISTS certificate_log_ct_entry (
  certificate_log_id INTEGER NOT NULL,
  log_id VARCHAR(255) NOT NULL,
  leaf_hash VARCHAR(255) NOT NULL,
  PRIMARY KEY (certificate_log_id, log_id, leaf_hash),
  FOREIGN KEY (certificate_log_id) REFERENCES certificate_log
);
