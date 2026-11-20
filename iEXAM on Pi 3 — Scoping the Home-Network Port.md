# iEXAM on Pi 3 — Scoping the Home-Network Port

Oct 13, 2026 · @Crypto Knight

The scope is settled at three nodes and a lightweight subset of the BAT and iEXAM. Everything is built and tested on Kali, then shipped to the Pi, with components added one phase at a time.

## Settled scope and the constraint it exposed

The scope is three nodes. Kali is the operator laptop and the build box. The router is a consumer home router. The Pi 3 is the edge node that runs collection and planning. One IP camera is the first monitored target, with more devices possible later. The port uses selected parts of the BAT and iEXAM, not the full SERA stack. Code is built and tested on Kali against the live router and camera, then shipped to the Pi over SSH.

The small topology resolved the Pi 3 worries. Three nodes make the planner state space trivial, so FastDownward on the Pi is no longer a memory risk. Building natively on the Pi removes cross-compilation. Claude Code on the Pi supplies the hosted-model path for the iEXAM explanation layer, so no local model is needed.

The simplification exposed one real constraint. A consumer router switches traffic. A monitoring node on a LAN port sees broadcast and multicast plus its own traffic, not the unicast flows between other devices. Edge monitoring therefore has a ceiling unless the Pi becomes the gateway, taps the link, or the router supports port mirroring, which consumer routers rarely do. For fingerprinting one camera this does not matter, because cameras announce themselves loudly. For traffic-flow analysis it does. The vantage decision waits until flow analysis is actually needed.

## Fingerprinting as collect then resolve

Fingerprinting is two steps, not one. First, collect the signature the device leaks on the wire. Second, resolve that signature to a device label. Collection always runs. Resolution has two possible methods, a database lookup or a trained classifier, both taking the same collected input.

No root on the target changes nothing here. Every network fingerprinting method is observational. What the lack of root rules out is an on-device agent, and neither method uses one.

The resolver method is deferred. A lookup matches the observed signature against a curated database, the IEEE OUI file, Fingerbank, and the make and model strings a camera returns over ONVIF or UPnP. It needs no training and scales with the size of the database, not with effort. A classifier predicts a label and needs training data, and for traffic features it needs a vantage the Pi does not have. The plan of record is lookup first for the catalogued majority, and a behavioral model only as a fallback for devices that leak nothing matchable, and only once a traffic tap exists. Phase 1 stubs the resolver so the pipeline runs before the method is chosen.

## Research claim and where Phase 1 lands

A planner over three nodes produces trivial output. The hardening options can be listed by hand, isolate the camera, patch it, firewall it. The novelty cannot live in the plan. It lives in the whole pipeline running autonomously on constrained edge hardware, from fingerprint to CVE map to PDDL to plan to recommendation, on a Pi. Build to that claim. If the goal is instead a demo or a teaching appliance, that is fine, but then nothing needs to be over-built. Name the contribution before the planner is built.

The BAT's actions are narrower at home than on the rack. On the rack the BAT SSHes into VMs to patch and disable services. Home IoT devices have no shell for the operator and cannot be patched by hand. So the home BAT either collects and recommends, or it acts on the router through firewall rules and segmentation, not on the devices. That scope is set when the BAT is built.

Phase 1 lands as collection only. One command on Kali against the camera produces a JSON evidence record with the MAC, the OUI vendor, the open ports, and the make, model, and firmware if the camera answers ONVIF or UPnP. The resolver and CVE steps are stubbed. There is no planner and no Pi yet. Validate the record on Kali, then move to Phase 2.
