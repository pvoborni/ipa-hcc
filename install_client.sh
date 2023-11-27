#!/bin/sh
set -ex

if [ -x /usr/libexec/platform-python ]; then
    PYTHON=/usr/libexec/platform-python
elif [ -x /usr/bin/python3 ]; then
    PYTHON=/usr/bin/python3
fi

SITELIB=$($PYTHON -c 'from sys import version_info as v; print("/usr/lib/python{}.{}/site-packages".format(v.major, v.minor))')

## install files
make -j1 install_python install_client install_client_prepare PYTHON=$PYTHON PYTHON_SITELIB=$SITELIB

# ensure correct SELinux labels
restorecon -R /usr/libexec/ipa-hcc /usr/lib/systemd/system/

# enable systemd servies
systemctl daemon-reload
/bin/systemctl enable ipa-hcc-client-prepare.service
/bin/systemctl enable ipa-hcc-auto-enrollment.service

# force schema cache update
rm -rf ~/.cache/ipa
