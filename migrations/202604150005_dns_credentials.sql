-- DNS 凭证列表（与 ACME 账号解耦，可复用）
CREATE TABLE IF NOT EXISTS dns_credentials (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(128) NOT NULL COMMENT '凭证别名（显示用）',
    provider         VARCHAR(64)  NOT NULL COMMENT 'dns_cloudflare / dns_dnspod / dns_aliyun / dns_he / http01',
    credentials_json TEXT         COMMENT '凭证 JSON，格式由 provider 决定',
    note             VARCHAR(512) DEFAULT '' COMMENT '备注',
    created_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_provider (provider)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 把旧的 acme_config 凭证迁移到新表（如果有数据）
INSERT INTO dns_credentials (name, provider, credentials_json, note)
SELECT
    CONCAT('迁移自 ACME 配置 (', provider, ')'),
    provider,
    credentials_json,
    '由旧 ACME 配置自动迁移'
FROM acme_config
WHERE credentials_json IS NOT NULL AND credentials_json != '' AND provider != 'http01'
LIMIT 1;

-- ACME 账号表中的 dns_provider / credentials_json 列已在新架构中废弃，
-- 但 DROP COLUMN IF EXISTS 仅在 MySQL 8.0.29+ 可用，为兼容旧版本此处不执行 DROP。
-- 这两列保留在表中对功能无影响（查询不再 SELECT 它们，写入也不再 INSERT/UPDATE）。
