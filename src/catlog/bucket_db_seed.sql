CREATE TABLE IF NOT EXISTS bucket_config (
  key TEXT NOT NULL PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS bucket_ct_entry (
  log_id VARCHAR(255) NOT NULL,
  leaf_hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS file_status (
  id INTEGER NOT NULL PRIMARY KEY,
  filename TEXT NOT NULL,
  upload_offset INTEGER NOT NULL,
  upload_complete INTEGER NOT NULL,
  upload_fingerprint_sha256 VARCHAR(255),
  committed INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS file_status_filename_idx ON file_status (filename);

CREATE TABLE IF NOT EXISTS file_status_ct_entry (
  file_status_id INTEGER NOT NULL,
  log_id VARCHAR(255) NOT NULL,
  leaf_hash VARCHAR(255) NOT NULL,
  FOREIGN KEY (file_status_id) REFERENCES file_status(id)
);
