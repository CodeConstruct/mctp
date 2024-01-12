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
conf.set10('MCTPD_RECOVER_NIL_UUID',
    get_option('unsafe-recover-nil-uuid'),
    description: 'Consider a nil UUID to be valid for endpoint recovery purposes',
)
conf.set10('MCTPD_WRITABLE_CONNECTIVITY',
    get_option('unsafe-writable-connectivity'),
    description: 'Allow writes to the Connectivity member of the au.com.CodeConstruct.MCTP.Endpoint interface on endpoint objects')

config_h = configure_file(
    output: 'config.h',
    configuration: conf,
)

util_sources = ['src/mctp-util.c']
netlink_sources = ['src/mctp-netlink.c']
ops_sources = ['src/mctp-ops.c']

executable('mctp',
    sources: ['src/mctp.c'] + netlink_sources + util_sources + ops_sources,
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
        ] + netlink_sources + util_sources + ops_sources,
        dependencies: libsystemd,
        install: true,
        install_dir: get_option('sbindir'),
    )

    mctpd_test = executable('test-mctpd',
        sources: [
            'src/mctpd.c',
            'tests/mctp-ops-test.c',
        ] + netlink_sources + util_sources,
        include_directories:  include_directories('src'),
        dependencies: libsystemd,
    )
endif

test_conf_data = configuration_data()
test_conf_data.set('testpaths',
  join_paths(meson.current_source_dir(), 'tests')
)
configure_file(
    input: 'tests/pytest.ini.in',
    output: 'pytest.ini',
    configuration: test_conf_data,
)

pytest = find_program('pytest', required: false)

if pytest.found()
    test('test-mctpd', pytest,
        args: '--tap',
        protocol: 'tap',
    )
endif
