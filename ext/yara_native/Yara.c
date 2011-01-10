// Include the Ruby headers and goodies
#include "ruby.h"
#include "Yara.h"
#include <yara.h>

static VALUE rb_mYara = Qnil;
static VALUE rb_cContext = Qnil;

// Prototype for the initialization method - Ruby calls this, not you
void Init_yara();

// The initialization method for this module
void Init_yara() {
  rb_mYara = rb_define_module("Yara");
  rb_cContext = rb_define_class_under(rb_mYara, "Context", rb_cObject);

}


