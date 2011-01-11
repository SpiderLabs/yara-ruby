#include "Rules.h"
#include <stdio.h>

VALUE rules_allocate(VALUE klass);
VALUE rules_compile_file(VALUE self, VALUE fname);
VALUE rules_compile_string(VALUE self, VALUE string);
VALUE rules_weight(VALUE self);
VALUE rules_current_namespace(VALUE self);
VALUE rules_namespaces(VALUE self);
VALUE rules_set_namespace(VALUE self, VALUE name);

static VALUE class_Rules = Qnil;

VALUE error_CompileError = Qnil;

void init_rules(VALUE mod) {
  class_Rules = rb_define_class_under(mod, "Rules", rb_cObject);
  rb_define_alloc_func(class_Rules, rules_allocate);

  error_CompileError = rb_define_class_under(class_Rules, "CompileError", rb_eStandardError);

  rb_define_method(class_Rules, "compile_file", rules_compile_file, 1);
  rb_define_method(class_Rules, "compile_string", rules_compile_string, 1);
  rb_define_method(class_Rules, "weight", rules_weight, 0);
  rb_define_method(class_Rules, "current_namespace", rules_current_namespace, 0);
  rb_define_method(class_Rules, "namespaces", rules_namespaces, 0);
  rb_define_method(class_Rules, "set_namespace", rules_set_namespace, 1);

}

void rules_mark(YARA_CONTEXT *ctx) { }

void rules_free(YARA_CONTEXT *ctx) {
  yr_destroy_context(ctx);
}

VALUE rules_allocate(VALUE klass) {
  YARA_CONTEXT *ctx = yr_create_context();

  return Data_Wrap_Struct(klass, rules_mark, rules_free, ctx);
}

VALUE rules_compile_file(VALUE self, VALUE rb_fname) {
  FILE * f;
  char * fname;
  YARA_CONTEXT *ctx;
  char error_message[256];

  Check_Type(rb_fname, T_STRING);
  fname = rb_str2cstr(rb_fname, NULL);

  if( !(f=fopen(fname, "r")) ) {
    rb_raise(error_CompileError, "No such file: %s", fname);
  } else {
    Data_Get_Struct(self, YARA_CONTEXT, ctx);

    if( yr_compile_file(f, ctx) != 0 ) {
      yr_get_error_message(ctx, error_message, sizeof(error_message));
      fclose(f);
      rb_raise(error_CompileError, "Syntax Error - %s(%d): %s", fname, ctx->last_error_line, error_message);
    }

    fclose(f);
  }
  return Qnil;
}

VALUE rules_compile_string(VALUE self, VALUE rb_rules) {
  YARA_CONTEXT *ctx;
  char *rules;
  char error_message[256];

  Check_Type(rb_rules, T_STRING);
  rules = rb_str2cstr(rb_rules, NULL);
  Data_Get_Struct(self, YARA_CONTEXT, ctx);

  if( yr_compile_string(rules, ctx) != 0) {
      yr_get_error_message(ctx, error_message, sizeof(error_message));
      rb_raise(error_CompileError, "Syntax Error - line(%d): %s", ctx->last_error_line, error_message);
  }

  return Qnil;
}

VALUE rules_weight(VALUE self) {
  YARA_CONTEXT *ctx;
  Data_Get_Struct(self, YARA_CONTEXT, ctx);
  return INT2NUM(yr_calculate_rules_weight(ctx));
}


VALUE rules_current_namespace(VALUE self) {
  YARA_CONTEXT *ctx;
  Data_Get_Struct(self, YARA_CONTEXT, ctx);
  if(ctx->current_namespace && ctx->current_namespace->name)
    return rb_str_new2(ctx->current_namespace->name);
  else
    return Qnil;
}

VALUE rules_namespaces(VALUE self) {
  YARA_CONTEXT *ctx;
  NAMESPACE *ns;
  VALUE ary = rb_ary_new();
  long unsigned int i = 0;

  Data_Get_Struct(self, YARA_CONTEXT, ctx);
  ns = ctx->namespaces;
  while(ns && ns->name) {
    rb_ary_store(ary, i, rb_str_new2(ns->name));
    ns = ns->next;
    i++;
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

VALUE rules_set_namespace(VALUE self, VALUE rb_namespace) {
  YARA_CONTEXT *ctx;
  NAMESPACE *ns = NULL;
  const char *name;

  Check_Type(rb_namespace, T_STRING);
  name = rb_str2cstr(rb_namespace, NULL);

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
