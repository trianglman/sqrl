CREATE TABLE `sqrl_nonce` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `nonce` CHAR(64) NOT NULL,
    `created` DATE DEFAULT (DATETIME('now','localtime')) ,
    `ip` INT UNSIGNED NOT NULL,
    `action` INT NOT NULL,
    `related_public_key` CHAR(44),
    `verified` TINYINT(1) DEFAULT 0,
    UNIQUE (`nonce`)
);

CREATE TABLE `sqrl_pubkey` (
    `id` INTEGER PRIMARY KEY AUTOINCREMENT,
    `public_key` CHAR(44) NOT NULL,
    `vuk` CHAR(44) DEFAULT NULL,
    `suk` CHAR(44) DEFAULT NULL,
    `disabled` INT(1) DEFAULT 0,
    UNIQUE (`public_key`)
);