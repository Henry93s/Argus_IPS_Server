#ifndef RULES_PARSER_H
#define RULES_PARSER_H

#include <regex.h>
#include <stdint.h>

typedef enum { RULE_TYPE_HEADER, RULE_TYPE_PAYLOAD } RuleType;

typedef struct Rule {
    int id;
    RuleType type;
    // Header 기반 fields
    uint32_t src_ip, dst_ip; // 'any' -> 0
    uint16_t src_port, dst_port; // 'any' -> 0
    uint8_t protocol; // 'any' -> 0
    uint8_t flags; // 
    // Payload 기반 fields
    char* content;
    regex_t pcre;
    int has_pcre;
    char* pcre_str;
    // 공통 fields
    char msg[256];
    struct Rule* next;
} Rule;

typedef struct {
    Rule* head;
    int count;
} RuleSet;

void rulesetInit(RuleSet* rs, const char* filepath);
void rulesetDestroy(RuleSet* rs);

#endif // RULES_PARSER_H