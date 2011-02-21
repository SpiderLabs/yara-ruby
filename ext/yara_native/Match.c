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

#include "Yara_native.h"
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

static VALUE 
MatchString_NEW(int offset, char *ident, char *buf, size_t buflen) {
  match_string *ms;
  VALUE rb_ms = Qnil;

  ms = (match_string *) malloc(sizeof(match_string));

  if (! ms)
    rb_sys_fail("Can't allocate MatchString");

  rb_ms = Data_Wrap_Struct(class_MatchString, 0, free, ms);

  ms->offset      = rb_iv_set(rb_ms, "@offset", INT2NUM(offset));
  ms->identifier  = rb_iv_set(rb_ms, "@identifier", 
                      rb_obj_freeze(rb_str_new2(ident)));
  ms->buffer      = rb_iv_set(rb_ms, "@buffer", 
                      rb_obj_freeze(rb_str_new(buf, buflen)));

  return rb_obj_freeze(rb_ms);
}

int 
Match_NEW_from_rule(RULE *rule, unsigned char *buffer, VALUE *match) {
  match_info *mi;
  VALUE rb_mi = Qnil;

  TAG *tag;
  STRING *string;
  MATCH *m;
  META *meta;

  if (!(rule->flags & RULE_FLAGS_MATCH))
    return 0;

  mi = (match_info *) malloc(sizeof(match_info));
  if (! mi )
    return 1;

  rb_mi = Data_Wrap_Struct(class_Match, 0, free, mi);

  mi->rule      = rb_iv_set(rb_mi, "@rule", rb_obj_freeze(rb_str_new2(rule->identifier)));
  mi->namespace = rb_iv_set(rb_mi, "@namespace", rb_obj_freeze(rb_str_new2(rule->namespace->name)));
  mi->tags      = rb_iv_set(rb_mi, "@tags", rb_ary_new());
  mi->strings   = rb_iv_set(rb_mi, "@strings", rb_ary_new());
  mi->meta      = rb_iv_set(rb_mi, "@meta", rb_hash_new());

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
       rb_ary_push(mi->strings, 
           MatchString_NEW(m->offset, 
             string->identifier, 
             buffer + m->offset, 
             m->length));
        m = m->next;
      }
    }
    string = string->next;
  }
  rb_obj_freeze(mi->strings);

  meta = rule->meta_list_head;
  while(meta) {
    if (meta->type == META_TYPE_INTEGER) {
      rb_hash_aset(mi->meta, 
          rb_str_new2(meta->identifier), 
          INT2NUM(meta->integer));
    }
    else if (meta->type == META_TYPE_BOOLEAN) {
      rb_hash_aset(mi->meta, 
          rb_str_new2(meta->identifier), 
          ((meta->boolean) ? Qtrue : Qfalse));
    }
    else {
      rb_hash_aset(mi->meta, 
          rb_str_new2(meta->identifier), 
          rb_obj_freeze(rb_str_new2(meta->string)));
    }

    meta = meta->next;
  }
  rb_obj_freeze(mi->meta);

  *(match) = rb_obj_freeze(rb_mi);

  return 0;
}

/* 
 * Document-method: rule
 *
 * call-seq:
 *      match.rule() -> String
 *
 * @return String The rule identifier string for this match.
 */
static VALUE match_rule(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->rule;
}

/* 
 * Document-method: namespace
 *
 * call-seq:
 *      match.namespace() -> String
 *
 * @return String The namespace for this match.
 */
static VALUE match_namespace(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->namespace;
}

/* 
 * Document-method: tags
 *
 * call-seq:
 *      match.tags() -> Array
 *
 * @return [String]   An array of tags for this match.
 */
static VALUE match_tags(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->tags;
}

/* 
 * Document-method: strings
 *
 * call-seq:
 *      match.strings() -> Array
 *
 * @return [Yara::MatchString]   An array of MatchString objects for this match.
 */
static VALUE match_strings(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->strings;
}

/* 
 * Document-method: meta
 *
 * call-seq:
 *      match.meta() -> Hash
 *
 * @return Hash   Keyed values of metadata for the match object.
 */
static VALUE match_meta(VALUE self) {
  match_info *mi;
  Data_Get_Struct(self, match_info, mi);
  return mi->meta;
}

/* 
 * Document-method: identifier
 *
 * call-seq:
 *      matchstring.identifier() -> String
 *
 * @return String   The identification label for the string.
 */
static VALUE matchstring_identifier(VALUE self) {
  match_string *ms;
  Data_Get_Struct(self, match_string, ms);
  return ms->identifier;
}

/* 
 * Document-method: offset
 *
 * call-seq:
 *      matchstring.offset() -> Fixnum
 *
 * @return Fixnum   The offset where the match occurred.
 */
static VALUE matchstring_offset(VALUE self) {
  match_string *ms;
  Data_Get_Struct(self, match_string, ms);
  return ms->offset;
}

/* 
 * Document-method: buffer
 *
 * call-seq:
 *      matchstring.buffer() -> String
 *
 * @return String   The data matched in the buffer.
 */
static VALUE matchstring_buffer(VALUE self) {
  match_string *ms;
  Data_Get_Struct(self, match_string, ms);
  return ms->buffer;
}

void 
init_Match() {
  VALUE module_Yara = rb_define_module("Yara");

/*
 * Document-class: Yara::Match
 *
 * Encapsulates a match object returned from Yara::Rules#scan_string or 
 * Yara::Rules#scan_file. A Match contains one or more MatchString objects.
 */
  class_Match = rb_define_class_under(module_Yara, "Match", rb_cObject);
  rb_define_method(class_Match, "rule", match_rule, 0);
  rb_define_method(class_Match, "namespace", match_namespace, 0);
  rb_define_method(class_Match, "tags", match_tags, 0);
  rb_define_method(class_Match, "strings", match_strings, 0);
  rb_define_method(class_Match, "meta", match_meta, 0);


/*
 * Document-class: Yara::MatchString
 *
 * Encapsulates an individual matched string location. One or more of these
 * will be available from a Match object.
 */
  class_MatchString = rb_define_class_under(module_Yara, "MatchString", rb_cObject);
  rb_define_method(class_MatchString, "identifier", matchstring_identifier, 0);
  rb_define_method(class_MatchString, "offset", matchstring_offset, 0);
  rb_define_method(class_MatchString, "buffer", matchstring_buffer, 0);
}


