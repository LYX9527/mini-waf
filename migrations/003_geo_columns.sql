-- 访问日志表增加 IP 归属地字段
ALTER TABLE access_logs ADD COLUMN country VARCHAR(10) DEFAULT NULL AFTER referer;
ALTER TABLE access_logs ADD COLUMN city VARCHAR(100) DEFAULT NULL AFTER country;
