
#ifndef RB_RULES_H_GUARD
#define RB_RULES_H_GUARD

#include <yara.h>
#include "ruby.h"

static VALUE class_Rules;
static VALUE error_CompileError;

void init_rules(VALUE ruby_namespace);

#endif
