# SPDX-License-Identifier: GPL-2.0
#
project(
    'mctp', 'c',
    meson_version: '>= 0.59.0',
    version: 'v2.0',
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
    description: 'Allow writes to the Connectivity member of the au.com.codeconstruct.MCTP.Endpoint1 interface on endpoint objects')

conf.set_quoted('MCTPD_CONF_FILE_DEFAULT',
    join_paths(get_option('prefix'), get_option('sysconfdir'), 'mctpd.conf'),
    description: 'Default configuration file path',
)

config_h = configure_file(
    output: 'config.h',
    configuration: conf,
)

util_sources = ['src/mctp-util.c']
netlink_sources = ['src/mctp-netlink.c']
ops_sources = ['src/mctp-ops.c']

toml_dep = declare_dependency(
    sources: ['lib/tomlc99/toml.c'],
    include_directories: include_directories('lib/tomlc99'),
)

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

executable('mctp-bench',
    sources: ['src/mctp-bench.c'] + util_sources,
)

if libsystemd.found()
    executable('mctpd',
        sources: [
            'src/mctpd.c',
        ] + netlink_sources + util_sources + ops_sources,
        dependencies: [libsystemd, toml_dep],
        install: true,
        install_dir: get_option('sbindir'),
    )

    mctpd_test = executable('test-mctpd',
        sources: [
            'src/mctpd.c',
            'tests/mctp-ops-test.c',
        ] + netlink_sources + util_sources,
        include_directories:  include_directories('src'),
        dependencies: [libsystemd, toml_dep],
    )
endif

tests = get_option('tests')
if tests
    # The test suite contains integration-style tests that we wish to isolate.
    # The tests drive mctpd's D-Bus interfaces and navigate relevant code paths
    # by mocking kernel and MCTP device behaviour. The mock behaviours are
    # implemented by encapsulating netlink and MCTP messages over Unix domain
    # sockets bound to mock implementations in the test suite.
    #
    # Isolate the test suite under its own D-Bus session to prevent test
    # behaviours impacting applications connected to the usual buses. To
    # implement the isolation we need to work under some constraints:
    #
    # 1. mctpd's implementation connects to a bus by invoking `sd_bus_default()`,
    #    which uses a combination of environment variables and session
    #    properties to determine whether to connect to the system bus or the
    #    session bus
    #
    # 2. dbus-run-session configures an isolated session bus and controls the
    #    relevant environment variables for influencing the application to
    #    connect to this isolated bus instance.
    #
    # `sd_bus_default()` selects the system bus if the application is
    # not running in a systemd user slice. From experience, in a Github
    # Action environment the system bus is selected by `sd_bus_default()`,
    # implying that they aren't exploiting systemd slices. However,
    # `sd_bus_default()` can be influenced to select the user session by setting
    # `DBUS_STARTER_BUS_TYPE=user` in the environment. At this point with a
    # naive approach we run up against 2, where `dbus-run-session` sanitises
    # that configuration away
    #
    # Invoke pytest via a shell script under `dbus-run-session` so we can
    # override the sanitation of `DBUS_STARTER_BUS_TYPE`, ensuring `test-mctpd`
    # connects to the isolated session bus prepared by `dbus-run-session`.
    pytest = find_program('pytest')
    script = 'export DBUS_STARTER_BUS_TYPE=user ; @0@ --tap'.format(pytest.full_path())
    sh = find_program('sh')
    dbus_run_session = find_program('dbus-run-session')

    test_conf_data = configuration_data()
    test_conf_data.set('testpaths',
      join_paths(meson.current_source_dir(), 'tests')
    )
    configure_file(
        input: 'tests/pytest.ini.in',
        output: 'pytest.ini',
        configuration: test_conf_data,
    )

    test('test-mctpd', dbus_run_session,
        depends: mctpd_test,
        args: [ sh.full_path(), '-c', script ],
        protocol: 'tap',
    )
endif
