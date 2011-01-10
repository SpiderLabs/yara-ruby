require 'mkmf'
require 'rbconfig'

extension_name = "yara_c"

dir_config(extension_name)

unless have_library("yara") and
       find_header("yara.h", "/usr/local/include")
  raise "You must install the yara library"
end

create_makefile(extension_name)

