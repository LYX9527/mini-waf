-- SSL 证书记录表
CREATE TABLE IF NOT EXISTS ssl_certs (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain      VARCHAR(255) NOT NULL UNIQUE,
    cert_path   VARCHAR(512) NOT NULL COMMENT 'fullchain.pem 路径',
    key_path    VARCHAR(512) NOT NULL COMMENT 'privkey.pem 路径',
    issuer      VARCHAR(512),
    not_before  DATETIME,
    not_after   DATETIME     COMMENT '证书过期时间',
    auto_renew  TINYINT(1)   NOT NULL DEFAULT 1 COMMENT '是否自动续签',
    acme_method VARCHAR(64)  DEFAULT 'http01' COMMENT 'http01 / dns_cloudflare / dns_dnspod / dns_aliyun',
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_not_after (not_after)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ACME 全局配置（单行，upsert 使用）
CREATE TABLE IF NOT EXISTS acme_config (
    id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email            VARCHAR(255)  NOT NULL DEFAULT '',
    provider         VARCHAR(64)   NOT NULL DEFAULT 'http01'
                         COMMENT 'http01 / dns_cloudflare / dns_dnspod / dns_aliyun',
    credentials_json TEXT          COMMENT '{"CF_Token":"xxx"} 等，存储前应加密',
    certbot_path     VARCHAR(512)  NOT NULL DEFAULT '/usr/bin/certbot',
    updated_at       DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 初始化一条默认 ACME 配置行（保证 SELECT 总能取到一行）
INSERT IGNORE INTO acme_config (id, email, provider) VALUES (1, '', 'http01');
