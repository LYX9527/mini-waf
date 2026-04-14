-- 访问日志表
CREATE TABLE IF NOT EXISTS access_logs (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address   VARCHAR(45)   NOT NULL,
    request_path VARCHAR(2048) NOT NULL,
    method       VARCHAR(10)   NOT NULL DEFAULT 'GET',
    status_code  INT           NOT NULL DEFAULT 200,
    is_blocked   TINYINT       NOT NULL DEFAULT 0,
    matched_rule VARCHAR(255)  DEFAULT NULL,
    user_agent   VARCHAR(1024) DEFAULT NULL,
    referer      VARCHAR(2048) DEFAULT NULL,
    created_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_created_at (created_at),
    INDEX idx_ip (ip_address),
    INDEX idx_blocked (is_blocked, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- IP 黑名单
CREATE TABLE IF NOT EXISTS ip_blacklist (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45)  NOT NULL UNIQUE,
    reason     VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- IP 白名单
CREATE TABLE IF NOT EXISTS ip_whitelist (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45)  NOT NULL UNIQUE,
    reason     VARCHAR(255) DEFAULT NULL,
    created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 系统配置表
CREATE TABLE IF NOT EXISTS system_settings (
    setting_key   VARCHAR(100) PRIMARY KEY,
    setting_value VARCHAR(500) NOT NULL,
    description   VARCHAR(255) DEFAULT NULL,
    updated_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 初始化默认配置
INSERT IGNORE INTO system_settings (setting_key, setting_value, description) VALUES
('rate_limit_threshold', '20', '每窗口期最大请求数'),
('rate_limit_window_secs', '10', '限流窗口秒数'),
('penalty_ban_score', '100', '封禁惩罚分阈值'),
('penalty_attack_score', '50', '单次攻击惩罚分'),
('penalty_ttl_secs', '3600', '惩罚分过期秒数'),
('token_ttl_secs', '3600', '通行令牌有效期秒数'),
('captcha_ttl_secs', '300', '验证码有效期秒数');
