-- SSL v2: 保存原始申请参数，续签时可继承
ALTER TABLE ssl_certs ADD COLUMN wildcard TINYINT(1) NOT NULL DEFAULT 0 COMMENT '是否通配符证书';
ALTER TABLE ssl_certs ADD COLUMN acme_account_id BIGINT UNSIGNED DEFAULT NULL COMMENT '申请时使用的 ACME 账号 ID';
ALTER TABLE ssl_certs ADD COLUMN dns_credential_id BIGINT UNSIGNED DEFAULT NULL COMMENT '申请时使用的 DNS 凭证 ID';
