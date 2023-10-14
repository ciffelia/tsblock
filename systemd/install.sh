#!/usr/bin/env bash

set -euxo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

install ../tsblock /usr/local/sbin/tsblock
install ./tsblock.service /etc/systemd/system/tsblock.service
