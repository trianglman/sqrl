CREATE TABLE `sqrl_nonce` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `nonce` CHAR(64) NOT NULL,
    `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `ip` INT UNSIGNED NOT NULL,
    UNIQUE (`nonce`)
);

CREATE TABLE `sqrl_pubkey` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `public_key` CHAR(64) NOT NULL,
    UNIQUE (`public_key`)
);