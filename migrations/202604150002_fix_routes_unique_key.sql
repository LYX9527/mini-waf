-- 将 routes 表的唯一约束从只有 path_prefix 改为 (path_prefix, host_pattern) 联合唯一
-- 这样允许同一路径前缀配置多个不同域名的路由条目
ALTER TABLE `routes`
    DROP INDEX `uk_path_prefix`,
    ADD UNIQUE KEY `uk_path_host` (`path_prefix`, `host_pattern`);
