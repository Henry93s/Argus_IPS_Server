// rules_parser.c
#define _GNU_SOURCE // for strcasestr
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "rules_parser.h"

// 문자열에서 옵션(key:value)을 파싱하는 헬퍼 함수
static char* parse_option(const char* options_str, const char* key) {
    char* key_with_colon = malloc(strlen(key) + 2);
    sprintf(key_with_colon, "%s:", key);

    const char* start = strcasestr(options_str, key_with_colon);
    if (!start) {
        free(key_with_colon);
        return NULL;
    }
    start += strlen(key_with_colon);

    // 따옴표로 묶인 값을 처리
    if (*start == '"') {
        start++;
        const char* end = strchr(start, '"');
        if (!end) {
            free(key_with_colon);
            return NULL;
        }
        int len = end - start;
        char* value = (char*)malloc(len + 1);
        strncpy(value, start, len);
        value[len] = '\0';
        free(key_with_colon);
        return value;
    } else { // 따옴표 없는 값 처리
        const char* end = strchr(start, ';');
        int len = (end) ? (end - start) : strlen(start);
        char* value = (char*)malloc(len + 1);
        strncpy(value, start, len);
        value[len] = '\0';
        free(key_with_colon);
        return value;
    }
}

void rulesetInit(RuleSet* rs, const char* filepath) {
    if (rs == NULL || filepath == NULL) return;

    FILE* fp = fopen(filepath, "r");
    if (fp == NULL) {
        perror("Failed to open rules file");
        return;
    }

    rs->head = NULL;
    rs->count = 0;
    char* line = NULL;
    size_t len = 0;
    int rule_id_counter = 1;

    while (getline(&line, &len, fp) != -1) {
        if (line[0] == '#' || line[0] == '\n') continue; // 주석이나 빈 줄은 건너뛰기

        Rule* new_rule = (Rule*)calloc(1, sizeof(Rule));
        if (!new_rule) continue;
        
        new_rule->id = rule_id_counter++;

        char* token;
        char* rest = line;
        
        // 1. Action (ALERT)
        token = strtok_r(rest, " ", &rest);
        // (현재는 ALERT만 지원)

        // 2. Protocol (TCP, UDP, ICMP)
        token = strtok_r(rest, " ", &rest);
        if (strcasecmp(token, "TCP") == 0) new_rule->protocol = IPPROTO_TCP;
        else if (strcasecmp(token, "UDP") == 0) new_rule->protocol = IPPROTO_UDP;
        else if (strcasecmp(token, "ICMP") == 0) new_rule->protocol = IPPROTO_ICMP;
        
        // 3. Src IP
        token = strtok_r(rest, " ", &rest);
        if (strcasecmp(token, "any") != 0) inet_pton(AF_INET, token, &new_rule->src_ip);
        
        // 4. Src Port
        token = strtok_r(rest, " ", &rest);
        if (strcasecmp(token, "any") != 0) new_rule->src_port = htons(atoi(token));
        
        // 5. Direction (->)
        strtok_r(rest, " ", &rest);
        
        // 6. Dst IP
        token = strtok_r(rest, " ", &rest);
        if (strcasecmp(token, "any") != 0) inet_pton(AF_INET, token, &new_rule->dst_ip);
        
        // 7. Dst Port
        token = strtok_r(rest, " ", &rest);
        if (strcasecmp(token, "any") != 0) new_rule->dst_port = htons(atoi(token));
        
        // 8. Options
        char* options_start = strchr(rest, '(');
        if (options_start) {
            char* options_end = strrchr(options_start, ')');
            if (options_end) *options_end = '\0';
            
            char* opt_val;

            // type
            opt_val = parse_option(options_start, "type");
            if (opt_val) {
                if (strcasecmp(opt_val, "header") == 0) new_rule->type = RULE_TYPE_HEADER;
                else if (strcasecmp(opt_val, "payload") == 0) new_rule->type = RULE_TYPE_PAYLOAD;
                free(opt_val);
            }
            
            // msg
            opt_val = parse_option(options_start, "msg");
            if (opt_val) {
                strncpy(new_rule->msg, opt_val, sizeof(new_rule->msg) - 1);
                free(opt_val);
            }
            
            // flags
            opt_val = parse_option(options_start, "flags");
            if(opt_val){
                if(strcasecmp(opt_val, "S") == 0) new_rule->flags = 0x02;
                // ... 다른 플래그들 추가 ...
                free(opt_val);
            }

            // content
            opt_val = parse_option(options_start, "content");
            if (opt_val) {
                new_rule->content = opt_val; // free는 나중에 destroy에서
            }
            
            // pcre
            opt_val = parse_option(options_start, "pcre");
            if (opt_val) {
                // pcre:"/.../i" 에서 패턴 부분만 추출
                char* pattern_start = strchr(opt_val, '/');
                char* pattern_end = strrchr(opt_val, '/');
                if (pattern_start && pattern_end && pattern_start != pattern_end) {
                    *pattern_end = '\0';
                    int cflags = REG_EXTENDED;
                    if (*(pattern_end + 1) == 'i') cflags |= REG_ICASE;
                    
                    // 원본 패턴
                    const char* raw_pattern = pattern_start + 1;

                    // 보정된 패턴 (역슬래시 2배로 늘려줌)
                    char* fixed_pattern = (char*)malloc(strlen(raw_pattern) * 2 + 1);
                    if (!fixed_pattern) {
                        fprintf(stderr, "malloc failed for regex pattern\n");
                        return;
                    }
                    char* dst = fixed_pattern;
                    for (const char* src = raw_pattern; *src; src++) {
                        if (*src == '\\') {
                            *dst++ = '\\'; // 한 번 더 추가
                        }
                        *dst++ = *src;
                    }
                    *dst = '\0';

                    if (regcomp(&new_rule->pcre, fixed_pattern, cflags) == 0) {
                        new_rule->has_pcre = 1;
                        // 원본 pcre 문자열 저장
                        new_rule->pcre_str = strdup(raw_pattern);
                    } else {
                        fprintf(stderr, "Failed to compile regex: %s\n", fixed_pattern);
                    }
                    free(fixed_pattern);
                }
                free(opt_val);
            }
        }
        
        // 연결 리스트에 추가
        new_rule->next = rs->head;
        rs->head = new_rule;
        rs->count++;
    }
    
    fclose(fp);
    if (line) free(line);
    printf("[Rules Parser] Loaded %d rules successfully.\n", rs->count);
}

void rulesetDestroy(RuleSet* rs) {
    if (rs == NULL) return;
    Rule* current = rs->head;
    while (current != NULL) {
        Rule* to_delete = current;
        current = current->next;
        if (to_delete->content) free(to_delete->content);
        if (to_delete->has_pcre) {
            regfree(&to_delete->pcre);
            if(to_delete->pcre_str) free(to_delete->pcre_str);
        }
        free(to_delete);
    }
}