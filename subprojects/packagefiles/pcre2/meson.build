project('pcre2', 'c', version: '10.42')

conf_data = configuration_data()

pcre2_chartables = configure_file(input : 'src/pcre2_chartables.c.dist',
  output : 'pcre2_chartables.c',
  configuration : conf_data)

pcre2_h = configure_file(input : 'src/pcre2.h.generic',
  output : 'pcre2.h',
  configuration : conf_data)

config_h = configure_file(input : 'src/config.h.generic',
  output : 'config.h',
  configuration : conf_data)

libpcre2_c_args = [
  '-DHAVE_CONFIG_H', # Default values from config.h
  '-DPCRE2_CODE_UNIT_WIDTH=8',
  '-DHAVE_MEMMOVE',
  '-DSUPPORT_JIT',
  '-DSUPPORT_PCRE2_8',
  '-DSUPPORT_UNICODE',
  '-DSUPPORT_VALGRIND',
  '-fvisibility=default',
]

pcre2_files = [
  'src/pcre2_auto_possess.c',
  pcre2_chartables,
  'src/pcre2_compile.c',
  'src/pcre2_config.c',
  'src/pcre2_context.c',
  'src/pcre2_convert.c',
  'src/pcre2_dfa_match.c',
  'src/pcre2_error.c',
  'src/pcre2_extuni.c',
  'src/pcre2_find_bracket.c',
  'src/pcre2_jit_compile.c',
  'src/pcre2_maketables.c',
  'src/pcre2_match.c',
  'src/pcre2_match_data.c',
  'src/pcre2_newline.c',
  'src/pcre2_ord2utf.c',
  'src/pcre2_pattern_info.c',
  'src/pcre2_script_run.c',
  'src/pcre2_serialize.c',
  'src/pcre2_string_utils.c',
  'src/pcre2_study.c',
  'src/pcre2_substitute.c',
  'src/pcre2_substring.c',
  'src/pcre2_tables.c',
  'src/pcre2_ucd.c',
  'src/pcre2_valid_utf.c',
  'src/pcre2_xclass.c',
]

pcre2_includes = [
  'src/',
  'src/sljit/',
]

libpcre2 = library('pcre2', pcre2_files,
  c_args: libpcre2_c_args,
  include_directories: pcre2_includes,
)

pcre2_dep = declare_dependency(
  link_with: libpcre2,
  include_directories: pcre2_includes
)
