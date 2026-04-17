INSERT IGNORE INTO system_settings (setting_key, setting_value, description) VALUES
('trust_upstream_proxy', '0', '信任上游代理IP头 (如 CF-Connecting-IP, 0=关闭, 1=开启)');
