/*
 *  yara-ruby - Ruby bindings for the yara malware analysis library.
 *  Eric Monti
 *  Copyright (C) 2011 Trustwave Holdings
 *  
 *  This program is free software: you can redistribute it and/or modify it 
 *  under the terms of the GNU General Public License as published by the 
 *  Free Software Foundation, either version 3 of the License, or (at your
 *  option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful, but 
 *  WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 *  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 *  for more details.
 *  
 *  You should have received a copy of the GNU General Public License along
 *  with this program. If not, see <http://www.gnu.org/licenses/>.
 *  
*/

#include "Match.h"
#include "Yara_native.h"
#include <stdio.h>

VALUE class_Rules = Qnil;

void rules_mark(YARA_CONTEXT *ctx) { }

void rules_free(YARA_CONTEXT *ctx) {
  yr_destroy_context(ctx);
}

VALUE rules_allocate(VALUE klass) {
  YARA_CONTEXT *ctx = yr_create_context();

  return Data_Wrap_Struct(klass, rules_mark, rules_free, ctx);
}

/* 
 * Document-method: compile_file
 *
 * call-seq:
 *      rules.compile_file(filename) -> nil
 *
 * Compiles rules taken from a file by its filename. This method
 * can be called more than once using multiple rules strings and
 * can be used in combination with compile_file.
 *
 * To avoid namespace conflicts, you can use set_namespace
 * before compiling rules.
 */
VALUE rules_compile_file(VALUE self, VALUE rb_fname) {
  FILE * file;
  char * fname;
  YARA_CONTEXT *ctx;
  char error_message[256];

  Check_Type(rb_fname, T_STRING);
  fname = RSTRING_PTR(rb_fname);

  if( !(file=fopen(fname, "r")) ) {
    rb_raise(error_CompileError, "No such file: %s", fname);
  } else {
    Data_Get_Struct(self, YARA_CONTEXT, ctx);

    if( yr_compile_file(file, ctx) != 0 ) {
      yr_get_error_message(ctx, error_message, sizeof(error_message));
      fclose(file);
      rb_raise(error_CompileError, "Syntax Error - %s(%d): %s", fname, ctx->last_error_line, error_message);
    }

    yr_push_file_name(ctx, fname);
    fclose(file);
    return Qtrue;
  }
}

/* 
 * Document-method: compile_string
 *
 * call-seq:
 *      rules.compile_string(rules_string) -> nil
 *
 * Compiles rules taken from a ruby string. This method
 * can be called more than once using multiple rules strings
 * and can be used in combination with compile_file.
 *
 * To avoid namespace conflicts, you can use set_namespace
 * before compiling rules.
 */
VALUE rules_compile_string(VALUE self, VALUE rb_rules) {
  YARA_CONTEXT *ctx;
  char *rules;
  char error_message[256];

  Check_Type(rb_rules, T_STRING);
  rules = RSTRING_PTR(rb_rules);
  Data_Get_Struct(self, YARA_CONTEXT, ctx);

  if( yr_compile_string(rules, ctx) != 0) {
      yr_get_error_message(ctx, error_message, sizeof(error_message));
      rb_raise(error_CompileError, "Syntax Error - line(%d): %s", ctx->last_error_line, error_message);
  }

  return Qtrue;
}

/* 
 * Document-method: weight
 *
 * call-seq:
 *      rules.weight() -> fixnum
 *
 * Returns a weight value for the compiled rules.
 */

VALUE rules_weight(VALUE self) {
  YARA_CONTEXT *ctx;
  Data_Get_Struct(self, YARA_CONTEXT, ctx);
  return INT2NUM(yr_calculate_rules_weight(ctx));
}

/* 
 * Document-method: current_namespace
 *
 * call-seq:
 *      rules.current_namespace() -> String
 *
 * Returns the name of the currently active namespace.
 */
VALUE rules_current_namespace(VALUE self) {
  YARA_CONTEXT *ctx;
  Data_Get_Struct(self, YARA_CONTEXT, ctx);
  if(ctx->current_namespace && ctx->current_namespace->name)
    return rb_str_new2(ctx->current_namespace->name);
  else
    return Qnil;
}

/* 
 * Document-method: namespaces
 *
 * call-seq:
 *      rules.namespaces() -> Array
 *
 * Returns the namespaces available in this rules context.
 */
VALUE rules_namespaces(VALUE self) {
  YARA_CONTEXT *ctx;
  NAMESPACE *ns;
  VALUE ary = rb_ary_new();

  Data_Get_Struct(self, YARA_CONTEXT, ctx);
  ns = ctx->namespaces;
  while(ns && ns->name) {
    rb_ary_push(ary, rb_str_new2(ns->name));
    ns = ns->next;
  }
  return ary;
}

NAMESPACE * find_namespace(YARA_CONTEXT *ctx, const char *name) {
  NAMESPACE *ns = ctx->namespaces;

  while(ns && ns->name) {
    if(strcmp(name, ns->name) == 0)
      return(ns);
    else
      ns = ns->next;
  }
  return (NAMESPACE*) NULL;
}

/* 
 * Document-method: set_namespace
 *
 * call-seq:
 *      rules.set_namespace(name) -> nil
 *
 * Sets the current namespace to the given name. If the namespace
 * does not yet exist it is added.
 *
 * To avoid namespace conflicts, you can use set_namespace
 * before compiling rules.
 */
VALUE rules_set_namespace(VALUE self, VALUE rb_namespace) {
  YARA_CONTEXT *ctx;
  NAMESPACE *ns = NULL;
  const char *name;

  Check_Type(rb_namespace, T_STRING);
  name = RSTRING_PTR(rb_namespace);

  Data_Get_Struct(self, YARA_CONTEXT, ctx);

  if (!(ns = find_namespace(ctx, name)))
      ns = yr_create_namespace(ctx, name);

  if (ns) {
    ctx->current_namespace = ns;
    return rb_namespace;
  } else {
    return Qnil;
  }

}

static int 
scan_callback(RULE *rule, unsigned char *buffer, unsigned int buffer_size, void *data) {
  int match_ret;
  VALUE match = Qnil;
  VALUE results = *((VALUE *) data);

  Check_Type(results, T_ARRAY);

  match_ret = Match_NEW_from_rule(rule, buffer, &match);
  if(match_ret == 0 && !NIL_P(match))
    rb_ary_push(results,match);

  return match_ret;
}

/* 
 * Document-method: scan_file
 *
 * call-seq:
 *      rules.scan_file(filename) -> nil
 *
 * Scans a file using the compiled rules supplied
 * with either compile_file or compile_string (or both).
 */
VALUE rules_scan_file(VALUE self, VALUE rb_fname) {
  YARA_CONTEXT *ctx;
  VALUE results;
  unsigned int ret;
  char *fname;

  Check_Type(rb_fname, T_STRING);
  results = rb_ary_new();
  Data_Get_Struct(self, YARA_CONTEXT, ctx);
  fname = RSTRING_PTR(rb_fname);

  ret = yr_scan_file(fname, ctx, scan_callback, &results);
  if (ret == ERROR_COULD_NOT_OPEN_FILE)
    rb_raise(error_ScanError, "Could not open file: '%s'", fname);
  else if (ret != 0)
    rb_raise(error_ScanError, "A error occurred while scanning: %s", 
        ((ret > MAX_SCAN_ERROR)? "unknown error" : SCAN_ERRORS[ret]));

  return results;
}


/* 
 * Document-method: scan_file
 *
 * call-seq:
 *      rules.scan_string(data) -> nil
 *
 * Scans a ruby string using the compiled rules supplied
 * with either compile_file or compile_string (or both).
 */
VALUE rules_scan_string(VALUE self, VALUE rb_dat) {
  YARA_CONTEXT *ctx;
  VALUE results;
  char *buf;
  long buflen;
  int ret;

  Check_Type(rb_dat, T_STRING);
  buf = RSTRING_PTR(rb_dat);
  buflen = RSTRING_LEN(rb_dat);

  results = rb_ary_new();

  Data_Get_Struct(self, YARA_CONTEXT, ctx);

  ret = yr_scan_mem(buf, buflen, ctx, scan_callback, &results);
  if (ret != 0)
    rb_raise(error_ScanError, "A error occurred while scanning: %s", 
        ((ret > MAX_SCAN_ERROR)? "unknown error" : SCAN_ERRORS[ret]));

  return results;
}

/*
 * Document-class: Yara::Rules
 *
 * Encapsulates a Yara context against which you can compile rules and
 * scan inputs.
 */
void init_Rules() {
  VALUE module_Yara = rb_define_module("Yara");

  class_Rules = rb_define_class_under(module_Yara, "Rules", rb_cObject);
  rb_define_alloc_func(class_Rules, rules_allocate);

  rb_define_method(class_Rules, "compile_file", rules_compile_file, 1);
  rb_define_method(class_Rules, "compile_string", rules_compile_string, 1);
  rb_define_method(class_Rules, "weight", rules_weight, 0);
  rb_define_method(class_Rules, "current_namespace", rules_current_namespace, 0);
  rb_define_method(class_Rules, "namespaces", rules_namespaces, 0);
  rb_define_method(class_Rules, "set_namespace", rules_set_namespace, 1);
  rb_define_method(class_Rules, "scan_file", rules_scan_file, 1);
  rb_define_method(class_Rules, "scan_string", rules_scan_string, 1);
}

