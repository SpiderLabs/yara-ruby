#include "Rules.h"
#include <stdio.h>

VALUE rules_allocate(VALUE klass);
VALUE rules_compile_file(VALUE self, VALUE object);
VALUE rules_compile_string(VALUE self, VALUE object);
VALUE rules_weight(VALUE self);

static VALUE class_Rules = Qnil;

VALUE error_CompileError = Qnil;

void init_rules(VALUE mod) {
  class_Rules = rb_define_class_under(mod, "Rules", rb_cObject);
  rb_define_alloc_func(class_Rules, rules_allocate);

  error_CompileError = rb_define_class_under(class_Rules, "CompileError", rb_eStandardError);

  rb_define_method(class_Rules, "compile_file", rules_compile_file, 1);
  rb_define_method(class_Rules, "compile_string", rules_compile_string, 1);
  rb_define_method(class_Rules, "weight", rules_weight, 0);

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

  Check_Type (rb_rules, T_STRING);
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

