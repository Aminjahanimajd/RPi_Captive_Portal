-- database: :memory:
-- WiFi Captive Portal — Database Schema
-- Integrated project: Web Programming + System Security (Federated Filesystem)

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    username      TEXT     NOT NULL UNIQUE,
    password_hash TEXT     NOT NULL,
    email         TEXT,
    role          TEXT     NOT NULL DEFAULT 'user',   -- 'admin' | 'user'
    mac_address   TEXT,
    is_active     INTEGER  NOT NULL DEFAULT 1,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    mac_address   TEXT     NOT NULL UNIQUE,
    hostname      TEXT,
    ip_address    TEXT,
    user_id       INTEGER  REFERENCES users(id) ON DELETE SET NULL,
    is_authorized INTEGER  NOT NULL DEFAULT 0,
    first_seen    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS federation_nodes (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    node_id       TEXT     NOT NULL UNIQUE,
    hostname      TEXT     NOT NULL,
    ip_address    TEXT     NOT NULL,
    port          INTEGER  NOT NULL DEFAULT 5000,
    public_key    TEXT,
    is_trusted    INTEGER  NOT NULL DEFAULT 0,
    last_seen     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS key_shards (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    shard_id      TEXT     NOT NULL UNIQUE,
    owner_node_id TEXT     NOT NULL,
    shard_data    TEXT     NOT NULL,              -- base64-encoded encrypted shard
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS access_log (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    device_mac    TEXT     NOT NULL,
    action        TEXT     NOT NULL,              -- 'connect','authorize','revoke','login','logout','register'
    ip_address    TEXT,
    timestamp     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
