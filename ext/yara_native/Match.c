/*
 *  yara-ruby - Ruby bindings for the yara malware analysis library.
 *  Eric Monti
 *  Copyright (C) 2011 Trustwave
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
#include <strings.h>
#include <stdlib.h>

VALUE class_Match = Qnil;
VALUE class_MatchString = Qnil;

const char * SCAN_ERRORS[] = {
  NULL,
  "insuficient memory",
  "duplicate rule identifier",
  "invalid char in hex string",
  "mismatched bracket",
  "skip at end",
  "invalid skip value",
  "unpaired nibble",
  "consecutive skips",
  "misplaced wildcard or skip",
  "undefined string",
  "undefined identifier",
  "could not open file",
  "invalid regular expression",
  "syntax error",
  "duplicate tag identifier",
  "unreferenced string",
  "duplicate string identifier",
  "callback error",
  "misplaced or operator",
  "invalid or operation syntax",
  "skip inside or operation",
  "nested or operation",
  "misplaced anonymous string",
  "could not map file",
  "zero length file",
  "invalid argument",
  "duplicate meta identifier",
  "includes circular reference",
  "incorrect external variable type",
};


typedef struct {
  VALUE rule;
  VALUE namespace;
  VALUE tags;
  VALUE strings;
  VALUE meta;
} match_info;

typedef struct {
  VALUE offset;
  VALUE identifier;
  VALUE buffer;
} match_string;

VALUE 
MatchString_NEW(int offset, char *ident, char *buf, size_t buflen) {
  match_string *ms;

  ms = (match_string *) malloc(sizeof(match_string));

  if (! ms)
    rb_raise(rb_eNoMemError, "Can't allocate MatchString");

  ms->offset      = INT2NUM(offset);
  ms->identifier  = rb_obj_freeze(rb_str_new2(ident));
  ms->buffer      = rb_obj_freeze(rb_str_new(buf, buflen));

  return rb_obj_freeze(Data_Wrap_Struct(class_MatchString, 0, free, ms));
}

int 
Match_NEW_from_rule(RULE *rule, unsigned char *buffer, VALUE *match) {
  match_info *mi;

  TAG *tag;
  STRING *string;
  MATCH *m;
  META *meta;

  if (!(rule->flags & RULE_FLAGS_MATCH))
    return 0;

  mi = (match_info *) malloc(sizeof(match_info));
  if (! mi )
    return 1;

  mi->rule      = rb_obj_freeze(rb_str_new2(rule->identifier));
  mi->namespace = rb_obj_freeze(rb_str_new2(rule->namespace->name));
  mi->tags      = rb_ary_new();
  mi->strings   = rb_ary_new();
  mi->meta      = rb_hash_new();

  tag = rule->tag_list_head;
  while (tag) {
    rb_ary_push(mi->tags, rb_obj_freeze(rb_str_new2(tag->identifier)));
    tag = tag->next;
  }
  rb_ary_sort_bang(mi->tags);
  rb_obj_freeze(mi->tags);

  string = rule->string_list_head;
  while(string) {
    if (string->flags & STRING_FLAGS_FOUND) {
      m = string->matches;
      while (m) {
       rb_ary_push(mi->strings, MatchString_NEW(m->offset, string->identifier, buffer + m->offset, m->length));
        m = m->next;
      }
    }
    string = string->next;
  }
  rb_obj_freeze(mi->strings);

  meta = rule->meta_list_head;
  while(meta) {
    // ... TODO
    meta = meta->next;
  }
  rb_obj_freeze(mi->meta);

  *(match) = rb_obj_freeze(Data_Wrap_Struct(class_Match, 0, free, mi));

  return 0;
}

VALUE match_rule(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->rule;
}

VALUE match_namespace(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->namespace;
}

VALUE match_tags(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->tags;
}

VALUE match_strings(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->strings;
}

VALUE match_meta(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->meta;
}

VALUE matchstring_identifier(VALUE self) {
  match_string *ms;
  Data_Get_Struct(self, match_string, ms);
  return ms->identifier;
}

VALUE matchstring_offset(VALUE self) {
  match_string *ms;
  Data_Get_Struct(self, match_string, ms);
  return ms->offset;
}

VALUE matchstring_buffer(VALUE self) {
  match_string *ms;
  Data_Get_Struct(self, match_string, ms);
  return ms->buffer;
}


void 
init_match(VALUE rb_ns) {
  class_Match = rb_define_class_under(rb_ns, "Match", rb_cObject);
  rb_define_method(class_Match, "rule", match_rule, 0);
  rb_define_method(class_Match, "namespace", match_namespace, 0);
  rb_define_method(class_Match, "tags", match_tags, 0);
  rb_define_method(class_Match, "strings", match_strings, 0);
  rb_define_method(class_Match, "meta", match_meta, 0);

  class_MatchString = rb_define_class_under(rb_ns, "MatchString", rb_cObject);
  rb_define_method(class_MatchString, "identifier", matchstring_identifier, 0);
  rb_define_method(class_MatchString, "offset", matchstring_offset, 0);
  rb_define_method(class_MatchString, "buffer", matchstring_buffer, 0);
}


