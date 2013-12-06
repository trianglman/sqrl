CREATE TABLE `sqrl_nonce` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `nonce` CHAR(64) NOT NULL,
    `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `ip` INT UNSIGNED NOT NULL,
    `action` INT NOT NULL,
    `related_public_key` CHAR(44),
    UNIQUE (`nonce`)
);

CREATE TABLE `sqrl_pubkey` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `public_key` CHAR(44) NOT NULL,
    `vuk` CHAR(44) NOT NULL,
    `suk` CHAR(44) NOT NULL,
    `disabled` INT(1) NOT NULL,
    UNIQUE (`public_key`)
);