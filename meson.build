# SPDX-License-Identifier: GPL-2.0
#
project(
    'mctp', 'c',
    meson_version: '>= 0.47.0',
    version: 'v1.1',
    license: 'GPLv2',
    default_options: [
        'warning_level=2',
    ],
)

cc = meson.get_compiler('c')
add_project_arguments('-Wno-unused-parameter', language : 'c')

libsystemd = dependency('libsystemd', version: '>=247', required: false)

conf = configuration_data()
conf.set10('HAVE_LINUX_MCTP_H',
    cc.has_header('linux/mctp.h'),
    description: 'Is linux/mctp.h available?'
)

config_h = configure_file(
    output: 'config.h',
    configuration: conf,
)

util_sources = ['src/mctp-util.c']
netlink_sources = ['src/mctp-netlink.c']

executable('mctp',
    sources: ['src/mctp.c'] + netlink_sources + util_sources,
    install: true,
)

executable('mctp-req',
    sources: ['src/mctp-req.c'] + util_sources,
)

executable('mctp-echo',
    sources: ['src/mctp-echo.c'] + util_sources,
)

if libsystemd.found()
    executable('mctpd',
        sources: [
            'src/mctpd.c',
        ] + netlink_sources + util_sources,
        dependencies: libsystemd,
        install: true,
        install_dir: get_option('sbindir'),
    )
endif
