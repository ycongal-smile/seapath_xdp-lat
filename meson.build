project('af-xdp-lat', 'c',
  version : '0.1.0',
  license : 'Apache-2.0',
)

# Dependencies
cc = meson.get_compiler('c')
clang = find_program('clang', version : '>= 10.0.0')

# Check for required libraries
libxdp_dep = dependency('libxdp', version : '>=1.3.0', required : true)
libbpf_dep = dependency('libbpf', version : '>=1.1.0', required : true)

# Check for required headers
if not cc.has_header('linux/bpf.h')
  error('linux/bpf.h header not found. Please install kernel headers.')
endif

if not cc.has_header('linux/if_ether.h')
  error('linux/if_ether.h header not found. Please install kernel headers.')
endif

# Main executable sources
main_sources = [
  'af_xdp_lat.c',
  'ftrace.c',
  'utils.c'
]

bpf_program_install_path = get_option('libdir') / meson.project_name()

# BPF program
bpf_program = custom_target('af_xdp_kern.o',
  input : 'af_xdp_kern.c',
  output : 'af_xdp_kern.o',
  command : [
    clang.full_path(),
    '-target', 'bpf',
    '-O2',
    '-g',
    '-Wall',
    '-Wextra',
    '-c',
    '@INPUT@',
    '-o', '@OUTPUT@',
  ],
  install : true,
  install_dir : bpf_program_install_path
)

# Configuration data for config.h
conf_data = configuration_data()
conf_data.set('BPF_PROGRAM_INSTALL_PATH', bpf_program_install_path)
conf_data.set('PREFIX', get_option('prefix'))
# Generate config.h
config_h = configure_file(
  input : 'config.h.in',
  output : 'config.h',
  configuration : conf_data
)


# Main executable
af_xdp_lat = executable('af_xdp_lat',
  main_sources,
  dependencies : [libxdp_dep, libbpf_dep],
  install : true,
  install_dir : get_option('bindir')
)

# Summary
summary({
  'prefix' : get_option('prefix'),
  'bindir' : get_option('prefix') / get_option('bindir'),
  'libxdp version' : libxdp_dep.version(),
  'libbpf version' : libbpf_dep.version(),
}, section : 'Directories and Dependencies')
