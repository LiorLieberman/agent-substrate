---
title: "gVisor Actors Without a Network Card"
linkTitle: "gVisor Without a Network Card"
weight: 20
status: preview
status_note: >
  Disabled by default behind the `NetlessGVisor` preview gate. It is a proof
  of concept, and its behavior and switches will change.
description: >
  Run gVisor actors with no network card and carry their traffic over a unix
  socket.
---

# gVisor Actors Without a Network Card

A gVisor actor normally gets a veth in its own network namespace, and nftables
outside the sandbox redirect its TCP connections to atunnel. With this feature
the actor's sandbox has no network card. An in-sandbox producer,
[tun2connect](https://github.com/aojea/agents.net), carries each TCP connection
to atunnel over a unix socket as an HTTP `CONNECT name:port`. See
[Network Egress](network-egress.md). This is the gVisor counterpart of
[MicroVM Actors Without a Network Card](netless-microvm.md).

## Enabling it

1. Run Substrate with `--preview=NetlessGVisor` (ate-setup's `preview`
   setting). ate-setup then builds tun2connect from `hack/tools/tun2connect`,
   stages it in the bucket that holds the microVM assets, and installs the
   `gvisor-netless` SandboxConfig: the `gvisor-default` one plus a
   `tun2connect` asset.
2. Create a gVisor WorkerPool annotated `workerpool.ate.dev/netless: "true"`
   that names that SandboxConfig:

   ```yaml
   apiVersion: ate.dev/v1
   kind: WorkerPool
   metadata:
     name: netless-gvisor
     annotations:
       workerpool.ate.dev/netless: "true"
     labels:
       network: netless
   spec:
     replicas: 1
     workerImage: <the ateworker-gvisor image>
     sandboxClasses:
     - name: gvisor
       configRef:
         name: gvisor-netless
   ```

Without the gate, the pool's workers refuse to start. The annotation and the
`tun2connect` asset go together: a pool with only one of them boots no actors.
An annotated pool also needs a worker image from this release. Turn the gate on
only once the egress gateway (atenet-egress) runs this release, since an older
gateway refuses a CONNECT that names a host.

## How it works

- The worker sets up no veth, nftables or DNS relay for the actor. runsc runs
  the sandbox in a network namespace that holds only `lo`, so gVisor's network
  stack has loopback and nothing else. `runsc port-forward`, which ingress
  takes, does not work with `--network=none`, so runsc keeps its default
  network mode. The worker pod drops `CAP_NET_RAW`, but keeps `CAP_NET_ADMIN`
  to bring `lo` up in that namespace. The actor's packets stay in gVisor's
  network stack: tun2connect ends each TCP connection there, and only its bytes
  reach the host, over a unix socket.
- Before the actor's containers, the worker starts tun2connect in the sandbox,
  as the `_tun2connect` container, from a read-only rootfs that holds a copy of
  the binary. tun2connect creates `tun0` with the default routes and answers
  DNS on `100.127.255.253`, which the containers' `/etc/resolv.conf` names.
  Only tun2connect gets `CAP_NET_ADMIN`, and it drops the capability once the
  device is up. The worker waits for the `/etc/resolv.conf` tun2connect writes
  for itself, which it writes once `tun0` and its routes are up.
- tun2connect sends each TCP connection as `CONNECT name:port` to
  `/run/tun2connect/egress.sock`, a unix socket the worker listens on in its
  own filesystem, out of the other workers' reach. atunnel opens the tunnel to
  the egress gateway with the actor's certificate.
- The gateway decides on the SNI or the Host as it does for every actor. It
  never resolves or dials the name in the CONNECT.
- Ingress and the wakeup probe go the other way: for each connection, the
  worker runs `runsc port-forward --stream`, which hands the sandbox a unix
  socket connection that gVisor joins to the actor's port on `127.0.0.1`. The
  actor has to listen on loopback, or on all addresses.

## One switch per WorkerPool

The switch is per WorkerPool, and the scheduler does not read it. See
[One switch per WorkerPool](netless-microvm.md#one-switch-per-workerpool) on
the microVM page: the same applies to gVisor pools, including using a new pool
to move actors to or from netless.

## Limitations

- TCP only. tun2connect answers DNS itself and drops other UDP.
- The DNS relay's policy check does not apply. The gateway's decision by name
  is the only check.
- Nothing restarts tun2connect. If it exits, the worker tears the actor down
  and reports it crashed, since the actor would have no network or ingress.
- Ingress reaches only port 80 and the containers' wakeup probe ports, as on
  microVM. It arrives on the actor's loopback, where other ports may serve the
  actor alone.
- gVisor's `port-forward` ends both directions of a stream as soon as one side
  stops sending, so the worker never passes a half-close on to the actor. If a
  caller stops sending on a CONNECT tunnel through ingress, the actor does not
  see the end of the stream, and the tunnel stays open until the actor closes it
  or is deactivated.
- MEMORY checkpoint and restore keep `tun0`. gVisor closes tun2connect's open
  connections to the egress socket when it saves, so egress connections open at
  the checkpoint do not survive it. New ones after the restore work.
- Ingress runs one runsc process per connection, and the wakeup probe one per
  attempt.
- tun2connect's gofer runs with `--host-uds=open` so tun2connect can connect to
  the egress socket. runsc applies the flag in each container's own gofer, so
  the actor's containers cannot reach host unix sockets.
