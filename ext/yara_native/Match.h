#ifndef RB_MATCH_H_GUARD
#define RB_MATCH_H_GUARD

#include "ruby.h"
#include <yara.h>

static VALUE class_Match;
static VALUE class_MatchString;

void 
init_match(VALUE ruby_namespace);

int
Match_NEW_from_rule(RULE * rule, unsigned char * buffer, VALUE * match);

extern const char * SCAN_ERRORS[];

#define MAX_SCAN_ERROR 29

#endif


