#!/bin/sh
# S1 (strona LAN) — uruchamiać w kontenerze S1. Idempotentny.
# eth1 R1 trunk | eth2 R2 trunk | eth3 węzeł eth0 | eth4 harness | eth5 UnMNG-R1 | eth6 UnMNG-R2
set -e
BR=$(ovs-vsctl list-br | head -1)
echo "bridge: $BR"
for p in eth1 eth2 eth3 eth4 eth5 eth6; do ovs-vsctl --may-exist add-port "$BR" "$p"; done

ovs-vsctl set port eth1 vlan_mode=trunk  trunks=110,210   # R1
ovs-vsctl set port eth2 vlan_mode=trunk  trunks=120,220   # R2 (rezerwa)
ovs-vsctl set port eth3 vlan_mode=trunk  trunks=110,120   # węzeł: eth0.110 / eth0.120
ovs-vsctl set port eth4 vlan_mode=trunk  trunks=110,120   # harness
ovs-vsctl set port eth5 vlan_mode=access tag=210          # klienci R1
ovs-vsctl set port eth6 vlan_mode=access tag=220          # klienci R2 (rezerwa)

# Pozostałe porty do martwego VLAN-u
for p in $(ovs-vsctl list-ports "$BR"); do
  case "$p" in eth1|eth2|eth3|eth4|eth5|eth6) ;; *) ovs-vsctl set port "$p" vlan_mode=access tag=999 ;; esac
done
ovs-vsctl show
