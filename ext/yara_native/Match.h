#ifndef RB_MATCH_H_GUARD
#define RB_MATCH_H_GUARD

#include "ruby.h"
#include <yara.h>

extern VALUE class_Match;
extern VALUE class_MatchString;

extern void 
init_match(VALUE ruby_namespace);

extern int
Match_NEW_from_rule(RULE * rule, unsigned char * buffer, VALUE * match);

extern const char * SCAN_ERRORS[];

#define MAX_SCAN_ERROR 29

#endif


