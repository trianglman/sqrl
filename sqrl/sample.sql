CREATE TABLE `sqrl_nonce` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `nonce` CHAR(64) NOT NULL,
    `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `ip` INT UNSIGNED NOT NULL,
    `action` INT UNSIGNED NOT NULL,
    `related_public_key` CHAR(44) DEFAULT NULL,
    `verified` TINYINT(1) DEFAULT 0,
    UNIQUE (`nonce`)
);

CREATE TABLE `sqrl_pubkey` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `public_key` CHAR(44) NOT NULL,
    `vuk` CHAR(44) NOT NULL,
    `suk` CHAR(44) NOT NULL,
    `disabled` TINYINT(1) NOT NULL DEFAULT 0,
    UNIQUE (`public_key`),
    INDEX (`vuk`)
);

CREATE TABLE `sqrl_nonce_relationship` (
    `old_nonce` CHAR(64) NOT NULL,
    `new_nonce` CHAR(64) NOT NULL,
    INDEX (`new_nonce`)
);