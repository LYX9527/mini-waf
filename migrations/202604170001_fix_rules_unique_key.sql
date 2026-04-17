-- 移除单一 keyword 唯一键，支持相同关键字不同匹配逻辑或作用域（例如 Header 里防御 SQLi，BODY 里也防御）
ALTER TABLE `rules`
    DROP INDEX `uk_keyword`,
    ADD UNIQUE KEY `uk_rule_identity` (`keyword`, `target_field`, `match_type`);
