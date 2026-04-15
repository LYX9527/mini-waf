-- ACME 账号表（支持多账号，不同域名可绑定不同账号）
CREATE TABLE IF NOT EXISTS acme_accounts (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(128)  NOT NULL COMMENT '账号别名（显示用）',
    email            VARCHAR(255)  NOT NULL,
    acme_server      VARCHAR(512)  NOT NULL DEFAULT 'https://acme-v02.api.letsencrypt.org/directory'
                         COMMENT 'Let''s Encrypt 正式版 / staging / ZeroSSL 等',
    dns_provider     VARCHAR(64)   NOT NULL DEFAULT 'http01'
                         COMMENT 'http01 / dns_cloudflare / dns_dnspod / dns_aliyun / dns_he',
    credentials_json TEXT          COMMENT 'JSON 格式的 DNS 凭证',
    is_default       TINYINT(1)    NOT NULL DEFAULT 0,
    status           VARCHAR(32)   NOT NULL DEFAULT 'active' COMMENT 'active / deactivated',
    note             VARCHAR(512)  DEFAULT '' COMMENT '备注',
    created_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_email (email),
    INDEX idx_default (is_default)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 把现有 acme_config 的数据迁移为默认账号（若存在）
INSERT INTO acme_accounts (name, email, dns_provider, credentials_json, is_default)
SELECT
    CONCAT('默认账号 (', email, ')'),
    email,
    provider,
    credentials_json,
    1
FROM acme_config
WHERE email IS NOT NULL AND email != ''
LIMIT 1;
