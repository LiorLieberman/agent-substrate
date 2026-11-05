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
> This is work in progress. The gate and the per-pool switch below exist, but a
> worker still boots actors with a network card.

## Enabling it

1. Run Substrate with `--preview=NetlessMicroVM` (ate-setup's `preview`
   setting).
2. Annotate a microvm WorkerPool with `workerpool.ate.dev/netless: "true"`.

Without the gate, the pool's workers refuse to start.

## One switch per WorkerPool

The switch is per WorkerPool: every actor placed on an annotated pool boots
without a network card. There is no Actor or ActorTemplate field for it while it
is a preview, so the Actor API does not change.

The scheduler does not read the annotation. Any microVM actor whose
`workerSelector` matches the pool can be placed on it. Give the pool a label,
and make the ActorTemplates that should, or should not, run there select on it.
