#!/bin/bash
set -e
if [ -z "${RM_FILE_OLD}" ]; then
    RM_FILE_OLD=1
fi
find /tmp/ -name "tmp*" -type d -mtime +$RM_FILE_OLD -exec rm -rf {} \;
