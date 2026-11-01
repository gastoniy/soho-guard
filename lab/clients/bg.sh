#!/bin/sh
# Tło benign: losowy cel, user-agent i przerwa (długi ogon). example.org celowo pominięty (beacon kontrolny).
RANDOM=$(( $(cksum /etc/hostname | cut -d' ' -f1) + $(date +%s) ))   # osobne ziarno per kontener
sleep $(( $(cksum /etc/hostname | cut -d' ' -f1) % 90 ))             # rozsunięty start
SITES="http://example.com https://www.wikipedia.org https://www.debian.org https://www.kernel.org
https://github.com https://www.mozilla.org https://www.python.org https://alpinelinux.org
https://www.openstreetmap.org https://www.gnu.org https://www.eff.org https://www.w3.org
https://news.ycombinator.com https://www.bbc.com https://www.python.org/downloads/"
UAS="Mozilla/5.0 curl/8.5 Wget/1.25 Python-urllib/3.12"
n_s=$(echo $SITES | wc -w); n_u=$(echo $UAS | wc -w)
while true; do
  s=$(echo $SITES | cut -d' ' -f$((RANDOM % n_s + 1)))
  u=$(echo $UAS   | cut -d' ' -f$((RANDOM % n_u + 1)))
  wget -q -T 10 -U "$u" -O /dev/null "$s"
  [ $((RANDOM % 6)) -eq 0 ] && nslookup "$(echo $s | cut -d/ -f3)" >/dev/null 2>&1
  r=$((RANDOM % 10))
  if   [ $r -lt 5 ]; then sleep $((RANDOM % 20 + 2))      # krótko
  elif [ $r -lt 8 ]; then sleep $((RANDOM % 120 + 30))    # średnio
  else                    sleep $((RANDOM % 600 + 180))   # długa cisza
  fi
done
