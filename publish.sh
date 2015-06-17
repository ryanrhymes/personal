#!/usr/bin/env bash

rm *~

scp -i ~/.ssh/id_cam -r * lw525@slogin.cl.cam.ac.uk:/home/lw525/public_html/