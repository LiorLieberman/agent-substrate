---
title: "MicroVM Actors Without a Network Card"
linkTitle: "MicroVM Without a Network Card"
weight: 19
status: preview
status_note: >
  Disabled by default behind the `NetlessMicroVM` preview gate. It is a proof
  of concept, and its behavior and switches will change.
description: >
  Boot microVM actors with no network card and carry their traffic over vsock.
---

# MicroVM Actors Without a Network Card

A microVM actor normally gets a virtual network card, and nftables outside the
sandbox redirect its TCP connections to atunnel. With this feature the actor's
VM boots with no network card. An in-guest producer,
[tun2connect](https://github.com/aojea/agents.net), carries each TCP connection
to atunnel over vsock as an HTTP `CONNECT name:port`. See
[Network Egress](network-egress.md).

> [!IMPORTANT]
> This is work in progress. Egress works. Ingress and wakeup probes do not
> reach the actor yet.

## Enabling it

1. Run Substrate with `--preview=NetlessMicroVM` (ate-setup's `preview`
   setting). ate-setup then builds tun2connect from `hack/tools/tun2connect`,
   stages it with the other microVM assets, and installs the `microvm-netless`
   SandboxConfig: the `microvm` one plus a `tun2connect` asset.
2. Create a microVM WorkerPool annotated `workerpool.ate.dev/netless: "true"`
   that names that SandboxConfig:

   ```yaml
   apiVersion: ate.dev/v1
   kind: WorkerPool
   metadata:
     name: netless
     annotations:
       workerpool.ate.dev/netless: "true"
     labels:
       network: netless
   spec:
     replicas: 1
     workerImage: <the ateworker-microvm image>
     sandboxClasses:
     - name: microvm
       configRef:
         name: microvm-netless
   ```

Without the gate, the pool's workers refuse to start. The annotation and the
`tun2connect` asset go together: a pool with only one of them boots no actors.
Turn the gate on only once the egress gateway
(atenet-egress) runs this release, since an older gateway refuses a CONNECT
that names a host.

## How it works

- The worker boots the VM with no virtio-net device, and sets up no network
  namespace, nftables or DNS relay for the actor on the host.
- Before the actor's containers, it starts tun2connect as a container in the
  guest. tun2connect creates `tun0` with IPv4 and IPv6 default routes and
  answers DNS on `100.127.255.253`, which the containers' `/etc/resolv.conf`
  names. Only tun2connect gets `CAP_NET_ADMIN` and a `/dev/net/tun` device
  node. It drops `CAP_NET_ADMIN` once the device is up, and keeps only
  `CAP_SETPCAP`. Its binary is a copy on a read-only bind.
- tun2connect sends each TCP connection as `CONNECT name:port` to host vsock
  port 1027. Cloud Hypervisor delivers it to `clh.sock_1027` in the VM's
  directory, where atunnel opens the tunnel to the egress gateway with the
  actor's certificate.
- The gateway decides on the SNI or the Host as it does for every actor. It
  never resolves or dials the name in the CONNECT.

## One switch per WorkerPool

The switch is per WorkerPool: every actor placed on an annotated pool boots
without a network card. There is no Actor or ActorTemplate field for it while it
is a preview, so the Actor API does not change.

The scheduler does not read the annotation. Any microVM actor whose
`workerSelector` matches the pool can be placed on it. Give the pool a label,
and make the ActorTemplates that should, or should not, run there select on it.

A MEMORY snapshot restores only on a worker with the same sandbox assets, so
a netless actor's snapshots stay on workers that use `microvm-netless`. A
worker also refuses a snapshot taken with the other network setup.

Use a new pool to move actors to or from netless. Converting an existing pool
makes its workers refuse actors while they roll, and its suspended actors lose
their MEMORY snapshots either way.

## Limitations

- TCP only. tun2connect answers DNS itself and drops other UDP.
- The DNS relay's policy check does not apply. The gateway's decision by name
  is the only check.
- Nothing restarts tun2connect if it exits, and the actor keeps running with no
  network.
- The actor's usage stats leave out tun2connect.
