ALTER TABLE rules ADD COLUMN target_field VARCHAR(50) NOT NULL DEFAULT 'URL';
ALTER TABLE rules ADD COLUMN match_type VARCHAR(50) NOT NULL DEFAULT 'Contains';

INSERT IGNORE INTO system_settings (setting_key, setting_value, description) 
VALUES ('custom_block_page', '', '自定义拦截页面 HTML（留空表示使用原生）');
