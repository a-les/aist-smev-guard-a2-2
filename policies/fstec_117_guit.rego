# policies/fstec_117_guit.rego
# Владелец: Селезнева Ольга Сергеевна (@wauwho) — Команда А2.2
# Автоматический аудит мер Приказа ФСТЭК России № 117 (в ред. № 137) и МД от 12.04.2026
package guit.fstec117

import rego.v1

# 1. Блокирующее нарушение МСЭ.3 / УПД.4: открыт административный порт SSH (22) или LLM-порт (8000) для @any
deny contains msg if {
    some rule in input.rules
    rule.effect == "allow"
    rule.subject_cidr_or_role in {"@any", "0.0.0.0/0", "*"}
    rule.port_range[0] <= 22
    rule.port_range[1] >= 22
    msg := sprintf("[CRITICAL I_block=0] Нарушение МСЭ.3 / УПД.4: открыт порт SSH 22 для %s в правиле %s (строка %d)", [rule.subject_cidr_or_role, rule.rule_id, rule.span.line_start])
}

deny contains msg if {
    some rule in input.rules
    rule.effect == "allow"
    rule.subject_cidr_or_role in {"@any", "0.0.0.0/0", "*"}
    rule.port_range[0] <= 8000
    rule.port_range[1] >= 8000
    msg := sprintf("[CRITICAL I_block=0] Нарушение ИИ.2 / ЗИС.3: прямой доступ @any к внутреннему порту LLM АИСТ (8000) в правиле %s (строка %d)", [rule.rule_id, rule.span.line_start])
}

# 2. Предупреждение ЗКС.2: риск фрагментации пакетов в ГОСТ-туннеле ViPNet при MTU > 1400
warnings contains msg if {
    some rule in input.rules
    rule.section == "tunnel"
    rule.mtu_value > 1400
    msg := sprintf("[WARNING ЗКС.2] Риск потери пакетов (MTU Drop) в туннеле ViPNet: MTU=%d > 1400 в правиле %s (строка %d)", [rule.mtu_value, rule.rule_id, rule.span.line_start])
}
