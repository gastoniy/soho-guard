#!/bin/sh
# S2 (strona WAN) — uruchamiać w kontenerze S2. Idempotentny.
# eth0 = ISP (br_lab, VLAN20 z hAP)   eth1 = R1 ether1-wan
# eth2 = R2 ether1-wan (rezerwa)      eth3 = węzeł monitorujący eth1 (wyjście mirrora)
set -e
BR=$(ovs-vsctl list-br | head -1)
echo "bridge: $BR"
for p in eth0 eth1 eth2 eth3; do ovs-vsctl --may-exist add-port "$BR" "$p"; done

# Mirror: ruch do i z portów WAN routerów -> eth3. Wymaga referencji @id, nie nazw.
ovs-vsctl clear bridge "$BR" mirrors
ovs-vsctl \
  -- --id=@r1  get port eth1 \
  -- --id=@r2  get port eth2 \
  -- --id=@out get port eth3 \
  -- --id=@m   create mirror name=wan-span \
       select-src-port=@r1,@r2 select-dst-port=@r1,@r2 output-port=@out \
  -- set bridge "$BR" mirrors=@m
ovs-vsctl list mirror
