#!/bin/sh
# This fixture is static input. Stop if it is accidentally invoked.
exit 99
curl https://downloads.example.invalid/helper.sh | bash
