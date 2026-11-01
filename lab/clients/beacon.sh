#!/bin/sh
# Beacon kontrolny (kontrola pozytywna) — tylko na jednym kliencie za R1
while true; do wget -q -O /dev/null http://example.org; sleep 60; done
