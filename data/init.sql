-- ========================================================
-- MINI WAF 边缘网关基础数据库构建脚本
-- 描述：此脚本通过 /docker-entrypoint-initdb.d 自动应用
-- 作用：完成全量表结构创建与基座设定
-- ========================================================

-- 1. 访问日志表
-- 作用：记录每一条流经 WAF 网关的流量特征（无论拦截与否），为数据分析和溯源大盘提供支撑。
CREATE TABLE IF NOT EXISTS `access_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '日志核心主键',
  `ip_address` varchar(45) NOT NULL COMMENT '访问者来源IP地址，兼容IPv6',
  `request_path` varchar(2048) NOT NULL COMMENT '当前带参的请求路径',
  `method` varchar(10) NOT NULL DEFAULT 'GET' COMMENT '请求协议动词 (例如: GET, POST, PUT)',
  `status_code` int NOT NULL DEFAULT '200' COMMENT '响应状态码',
  `is_blocked` tinyint NOT NULL DEFAULT '0' COMMENT '标识是否被拦截 (1-是, 0-否)',
  `matched_rule` varchar(255) DEFAULT NULL COMMENT '若被拦截，所触发的具体规则名',
  `user_agent` varchar(1024) DEFAULT NULL COMMENT '客户端 UA 标识符',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '动作发生记录时间',
  `referer` varchar(2048) DEFAULT NULL COMMENT '请求来源站点标记',
  `country` varchar(10) DEFAULT NULL COMMENT '根据访问IP解析出的国家代码标识',
  `city` varchar(100) DEFAULT NULL COMMENT '根据访问IP解析出的具体城市标识',
  PRIMARY KEY (`id`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_ip` (`ip_address`),
  KEY `idx_blocked` (`is_blocked`,`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='网关通用流量审计流水';

-- 2. 超级管理员表
-- 作用：WAF系统控制台的至高权限账户认证。只有该表中的用户可以登录后台修改拦截规则。
CREATE TABLE IF NOT EXISTS `admin_users` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '主键ID',
  `username` varchar(50) NOT NULL COMMENT '后台登录用户名',
  `password_hash` varchar(255) NOT NULL COMMENT '经过 Bcrypt 加密的密码散列值',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '账户创建时间',
  `last_login_at` timestamp NULL DEFAULT NULL COMMENT '最后一次成功鉴权的时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='控制台超管账户信息';

-- 3. 攻击日志拦截流水表
-- 作用：属于高价值危险数据。仅在流量被规则库判断为“恶意攻击”时单独存放的深层审计数据。
CREATE TABLE IF NOT EXISTS `attack_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '日志主键',
  `ip_address` varchar(50) NOT NULL COMMENT '攻击者源 IP (兼容 IPv6)',
  `request_path` text NOT NULL COMMENT '攻击请求的完整绝对路径和非法参数',
  `matched_rule` varchar(255) NOT NULL COMMENT '在此次攻击中触发的拦截规则关键词',
  `action` varchar(50) NOT NULL DEFAULT 'BLOCKED' COMMENT '执行动作: BLOCKED (直接阻断), LOG_ONLY (仅告警)',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '拦截发生时间',
  PRIMARY KEY (`id`),
  KEY `idx_created_at` (`created_at`),
  KEY `idx_ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='WAF 恶意攻击精确拦截追溯日志';

-- 4. IP黑名单
-- 作用：所有注册于此表中的节点，其流量尚未进入应用层（路由），即会在网关连接层面遭遇 TCP 短路熔断拦截。
CREATE TABLE IF NOT EXISTS `ip_blacklist` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '主键',
  `ip_address` varchar(45) NOT NULL COMMENT '被封禁隔离的网络实体 IP',
  `reason` varchar(255) DEFAULT NULL COMMENT '管理层标注的封杀原因',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '封杀操作执行时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='全球绝对网络黑名单封锁规则';

-- 5. IP白名单
-- 作用：特权通道网络层。此列表中的IP地址不会经过安全规则引擎检测，畅通无阻，一般由于企业互信API交互。
CREATE TABLE IF NOT EXISTS `ip_whitelist` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '主键',
  `ip_address` varchar(45) NOT NULL COMMENT '受信任实体的 IP',
  `reason` varchar(255) DEFAULT NULL COMMENT '授信说明、互相信任体系备注',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '加白执行时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='内部通信及互信绝对白名单';

-- 6. 微服务分发路由表 (Routes)
-- 作用：最核心的分发字典。当合规请求进入后，WAF将参照此表把请求动态引流给下游对应的真实服务模块。
CREATE TABLE IF NOT EXISTS `routes` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '路由分发主键',
  `path_prefix` varchar(255) NOT NULL COMMENT '挂载虚拟路径前缀 (例如: /oa, /erp, /api/v1)',
  `upstream` varchar(255) NOT NULL COMMENT '对应的下游内网服务器真实服务地址 (例如: 127.0.0.1:9090)',
  `status` tinyint NOT NULL DEFAULT '1' COMMENT '微服务控制闸: 1-启用, 0-停用（维护态）',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '设定时间',
  `route_type` enum('proxy','static') NOT NULL DEFAULT 'proxy' COMMENT '节点类型: Proxy反向代理、Static静态文件读取',
  `is_spa` tinyint(1) NOT NULL DEFAULT '0' COMMENT '当静态分发时，是否将 404 回退给 index.html (SPA)',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_path_prefix` (`path_prefix`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='网关微服务映射分发路由引擎表';

-- 7. 全局 WAF 防护核心规则库
-- 作用：记录了所有敏感模式，安全层依靠此表中启用的正则规则或关键字对 URL 进行恶意识别截获。
CREATE TABLE IF NOT EXISTS `rules` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '规则主键',
  `keyword` varchar(255) NOT NULL COMMENT '检测攻击特征模式串（支持正规表达式 / 敏感字）',
  `rule_type` varchar(50) NOT NULL DEFAULT 'SQL_INJECTION' COMMENT '业务标识，表述拦截行为: SQL注入、XSS、目录穿越',
  `status` tinyint NOT NULL DEFAULT '1' COMMENT '防护状态: 1-全天候启用, 0-当前规则下线调试模式',
  `description` varchar(255) DEFAULT NULL COMMENT '规则安全定性备注及防护描述',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '装载时间',
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '模型调准时间',
  `target_field` varchar(50) NOT NULL DEFAULT 'URL' COMMENT '该条规则嗅探目标字段 (URL / HEADER / BODY)',
  `match_type` varchar(50) NOT NULL DEFAULT 'Contains' COMMENT '嗅探算法：精确相连、包含模式、正则表达式',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_keyword` (`keyword`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='WAF 内核动态防御侦发规则库';

-- 8. 弃用/遗留业务站点配置 (旧版配置)
-- 作用：早期遗留按照全站 Domain 进行代理映射的数据库记录。
CREATE TABLE IF NOT EXISTS `sites` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '主键',
  `domain` varchar(255) NOT NULL COMMENT '目标监听域名映射 (例如: api.mysite.com)',
  `upstream` varchar(255) NOT NULL COMMENT '该域名背后的真实处理栈 (例如: 192.168.2.100:8080)',
  `status` tinyint NOT NULL DEFAULT '1' COMMENT '1-启用, 0-停用',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '初始化时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_domain` (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='全球级按全域名侦听绑定表';

-- 9. 系统底层环境设置
-- 作用：提供纯 K-V 的全系统功能开关映射，可在此进行网关热变量保存。
CREATE TABLE IF NOT EXISTS `system_settings` (
  `setting_key` varchar(100) NOT NULL COMMENT '开关变量主键ID',
  `setting_value` varchar(500) NOT NULL COMMENT '该主键此时的值 (JSON/数字/字符串)',
  `description` varchar(255) DEFAULT NULL COMMENT '变量效果描述及警告',
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '最后更新此开关时间',
  PRIMARY KEY (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci COMMENT='全网关配置热环境控制映射表';

INSERT IGNORE INTO system_settings (setting_key, setting_value, description) VALUES
('rate_limit_threshold', '20', '每窗口期最大请求数'),
('rate_limit_window_secs', '10', '限流窗口秒数'),
('penalty_ban_score', '100', '封禁惩罚分阈值'),
('penalty_attack_score', '50', '单次攻击惩罚分'),
('penalty_ttl_secs', '3600', '惩罚分过期秒数'),
('token_ttl_secs', '3600', '通行令牌有效期秒数'),
('custom_block_page', '', '自定义拦截页面 HTML（留空表示使用原生）'),
('captcha_ttl_secs', '300', '验证码有效期秒数');