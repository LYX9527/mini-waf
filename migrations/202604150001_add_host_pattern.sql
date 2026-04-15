-- 为 routes 表新增 host_pattern 字段
-- 用于虚拟主机路由匹配（为空则匹配所有域名）
ALTER TABLE `routes`
    ADD COLUMN `host_pattern` VARCHAR(255) NULL DEFAULT NULL
        COMMENT '域名匹配模式，如 api.example.com 或 *.example.com，为空则不限域名'
    AFTER `path_prefix`;
