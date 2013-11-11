CREATE TABLE `sqrl_nonce` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY,
    `nonce` CHAR(64) NOT NULL,
    `created` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `ip` INT UNSIGNED NOT NULL,
    `action` VARCHAR NOT NULL
    `related_public_key` CHAR(44) DEFAULT NULL,
    UNIQUE (`nonce`)
);

CREATE TABLE `sqrl_pubkey` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY,
    `public_key` CHAR(44) NOT NULL,
    `vuk` CHAR(44) NOT NULL,
    `suk` CHAR(44) NOT NULL,
    `disabled` TINYINT(1) NOT NULL DEFAULT 0,
    UNIQUE (`public_key`),
    INDEX (`vuk`)
);