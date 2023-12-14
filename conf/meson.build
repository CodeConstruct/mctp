systemd = dependency('systemd')

if systemd.found()
    servicedir = systemd.get_variable('systemdsystemunitdir')
    unit_files = [
        'mctp-local.target',
        'mctp.target',
        'mctpd.service',
    ]

    foreach unit : unit_files
    configure_file(input: unit,
                   output: unit,
                   copy: true,
                   install_dir: servicedir)
    endforeach
endif

