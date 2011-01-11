#include "errors.h"
#include "ruby.h"

VALUE error_CompileError = Qnil;
VALUE error_ScanError = Qnil;

void
init_errors(VALUE rb_ns) {
  error_CompileError = rb_define_class_under(rb_ns, "CompileError", rb_eStandardError);
  error_ScanError = rb_define_class_under(rb_ns, "ScanError", rb_eStandardError);
}
