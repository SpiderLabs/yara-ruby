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

#include "ruby.h"
#include <yara.h>

#include "Yara_native.h"
#include "Rules.h"

VALUE error_CompileError = Qnil;
VALUE error_ScanError = Qnil;

static VALUE module_Yara = Qnil;

void Init_yara_native() {
  yr_init();

  module_Yara = rb_define_module("Yara");

  error_CompileError = rb_define_class_under(module_Yara, "CompileError", rb_eStandardError);
  error_ScanError = rb_define_class_under(module_Yara, "ScanError", rb_eStandardError);

  init_rules(module_Yara);
}



