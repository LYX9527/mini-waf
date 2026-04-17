-- WAF v2: Advanced Features Migration
-- 1. Rules: Add "action" for Observe mode.
ALTER TABLE `rules` ADD COLUMN `action` varchar(50) NOT NULL DEFAULT 'Block' COMMENT 'Block OR Log';

-- 2. Routes: Add route-specific rate limiting
ALTER TABLE `routes` ADD COLUMN `rate_limit_threshold` int DEFAULT NULL COMMENT 'Route specific QPS threshold. Overrides global limit.';
