#!/usr/bin/env bash
out=$1
echo "ts,mem_avail_mb,mem_used_mb,swap_used_mb,load1,clickhouse_mem,zeek_rss_mb" > "$out"
while true; do
  read -r _ total used free shared buff avail < <(free -m | awk '/^Mem:/')
  swap=$(free -m | awk '/^Swap:/{print $3}')
  load=$(cut -d' ' -f1 /proc/loadavg)
  ch=$(docker stats --no-stream --format '{{.MemUsage}}' rita-clickhouse | cut -d/ -f1 | tr -d ' ')
  zk=$(ps -C zeek -o rss= | awk '{s+=$1} END{print int(s/1024)}')
  echo "$(date -u +%FT%T),$avail,$used,$swap,$load,$ch,$zk" >> "$out"
  sleep 1
done
