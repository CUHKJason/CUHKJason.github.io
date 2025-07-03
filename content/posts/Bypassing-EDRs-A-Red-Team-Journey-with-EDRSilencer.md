---
title: "Bypassing EDRs: A Red Team Journey with EDRSilencer and WFP Filter Arbitration"
date: 2025-07-02T20:00:00+08:00
draft: false
categories: 
 - redteam
tags:
 - redteam
 - wfp
 - EDR
summary: "Share my recent experience on using the EDRSilencer to block EDRs~"
---

## Introduction

[EDRSilencer](https://github.com/netero1010/EDRSilencer), a well-known red team tool, uses the Windows Filtering Platform (WFP) to block Endpoint Detection and Response (EDR) telemetry, creating blind spots for defenders. Despite its long presence and established detections, I recently used EDRSilencer in a red team engagement, uncovering fascinating challenges and insights about WFP Filter Arbitration. In this blog, I’ll share my experience, analyze why some EDRs resisted EDRSilencer’s default approach, and detail how I bypassed its protections by leveraging WFP’s nuances, with a nod to EDRSilencer’s author, [Chris Au](https://github.com/netero1010), for his help. I’ll also share recommendations for EDR vendors to harden their defenses.

## Red Team Engagement: EDRSilencer in Action

During a recent engagement, after gaining local admin privileges on a victim machine, I deployed EDRSilencer to disrupt EDR telemetry. Executing `EDRSilencer.exe blockedr` successfully blocked **Kaspersky**’s outbound traffic,  however, another well-known EDR (referred to as **EDR_A**) remained unaffected, even after adding its primary service executable to EDRSilencer’s EDR process list.  

Digging into EDRSilencer’s GitHub issues ([Issue #19](https://github.com/netero1010/EDRSilencer/issues/19)) and analyzing the `netstat` result, I learned that this EDR’s telemetry often operates at the kernel level and originates from the System process (PID 4) rather than user-mode processes. Chris shared a private EDRSilencer version that targeted EDR_A’s remote IPs instead of the user-mode processes, but it still failed to block the agent from connecting back to the cloud server.  

I then attempted to block the System process using `FwpmGetAppIdFromFileName0(L"SYSTEM", &appId)`, but this also failed. Suspecting WFP sublayer weight issues, I explored another issue ([Issue #20](https://github.com/netero1010/EDRSilencer/issues/20)) and modified EDRSilencer’s code to create a custom sublayer with the highest weight `0xFFFF`:

- **Sublayer**: `TestFilterSublayer_highest`, weight `0xFFFF`, with `FWPM_SUBLAYER_FLAG_PERSISTENT`.
- **Filter**: Block outbound IPv4 traffic for app ID `SYSTEM`, applied to `FWPM_LAYER_ALE_AUTH_CONNECT_V4`.

Despite this, EDR_A’s telemetry still remain persisted. After some discussions with Chris, we believed that EDR_A may use permit filters to whitelist their traffic. To investigate, I developed a Beacon Object File (BOF), adapted from [Aon’s Cyber Labs EDRSilencer-BOF](https://github.com/AonCyberLabs/EDRSilencer-BOF) to enumerate WFP filters and sublayers. This revealed that EDR_A’s custom sublayer also had the maximum weight (`0xFFFF`), causing my sublayer to be assigned `0xFFFE`. Moreover,  EDR_A’s permit filters, applied to `FWPM_LAYER_ALE_AUTH_CONNECT_V4` layer, used `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, a “hard permit” flag that overrides block filters in lower-weighted sublayers. This led me to study WFP Filter Arbitration and devise a new approach.
>> Access control on WFP sublayer and filter is another place to be pay attention, but we are not going to discuss this topic in this blog.

## Understanding WFP Filter Arbitration

[WFP Filter Arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration) determines how conflicting filters (e.g., block vs. permit) are resolved. Key terms include:

- **Layer**: A stage in the WFP processing pipeline where filters are applied (e.g., `FWPM_LAYER_OUTBOUND_TRANSPORT_V4` for transport-layer outbound traffic).
- **Sublayer**: A subdivision within a layer, prioritized by a weight (0 to `0xFFFF`). Higher-weighted sublayers are evaluated first.
- **Filter**: A rule specifying an action (e.g., block, permit) for matching traffic, with its own weight within a sublayer.
- **Weight**: A numeric value determining precedence within sublayers or filters.
- **Hard Permit (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`)**: A flag ensuring a permit filter’s action is final within the same layer, overriding lower-weighted sublayer blocks.

WFP processes filters in a specific order for outbound traffic (below is a simple demonstration):
1. `FWPM_LAYER_OUTBOUND_IPPACKET_V4`: Packet-level filtering.
2. `FWPM_LAYER_OUTBOUND_TRANSPORT_V4`: Transport-layer filtering (e.g., TCP/UDP).
3. `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4`: Resource allocation (e.g., socket binding).
4. `FWPM_LAYER_ALE_AUTH_CONNECT_V4`: Connection authorization.
5. `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4`: Established flow processing. 

Within a layer, sublayers are evaluated by weight (highest first), and within a sublayer, filters are prioritized by filter weight (highest first). A block filter typically overrides a permit filter regardless of the filter and sublayer weight, but `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` ensures a permit filter’s dominance against lower-weighted sublayer block filters in the same layer.

## Bypassing EDR_A: Blocking at FWPM_LAYER_OUTBOUND_TRANSPORT_V4

Realizing EDR_A’s hard permit filters in `FWPM_LAYER_ALE_AUTH_CONNECT_V4` were thwarting my blocks, I hypothesized that applying a block filter earlier in the WFP pipeline could preempt EDR_A’s permits. I conducted local tests targeting Google’s IP (142.250.71.174) across the five outbound IPv4 layers to understand WFP arbitration.

### Test Cases and Results

The table below summarizes my test cases, comparing permit and block filters across layers, sublayers, weights, and the `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` flag, with a screenshot of the test result.

| Case | Permit Filter Layer | Permit Sublayer Weight | Permit Filter Weight | Permit Flag | Block Filter Layer | Block Sublayer Weight | Block Filter Weight | Block Flag | Result | Result screenshot |
|------|---------------------|------------------------|----------------------|-------------|--------------------|-----------------------|---------------------|------------|--------|-------|
| 1    | ALE_AUTH_CONNECT_V4 | Same                   | Same                 | None        | ALE_AUTH_CONNECT_V4 | Same                  | Same                | None       | Block  | [test1](/files/EDRs/test1.png) |
| 2    | ALE_AUTH_CONNECT_V4 | Same                   | Higher               | None        | ALE_AUTH_CONNECT_V4 | Same                  | Lower               | None       | Permit | [test2](/files/EDRs/test2.png) |
| 3    | ALE_AUTH_CONNECT_V4 | Same                   | Same                 | CLEAR_ACTION_RIGHT | ALE_AUTH_CONNECT_V4 | Same                  | Same                | None       | Block  | [test3](/files/EDRs/test3.png) |
| 4    | ALE_AUTH_CONNECT_V4 | Higher                 | Same                 | None        | ALE_AUTH_CONNECT_V4 | Lower                 | Same                | None       | Block  | [test4](/files/EDRs/test4.png) |
| 5    | ALE_AUTH_CONNECT_V4 | Higher                 | Higher               | None        | ALE_AUTH_CONNECT_V4 | Lower                 | Lower               | None       | Block  | [test5](/files/EDRs/test5.png) |
| 6    | ALE_AUTH_CONNECT_V4 | Higher                 | Same                 | CLEAR_ACTION_RIGHT | ALE_AUTH_CONNECT_V4 | Lower                 | Same                | None       | Permit | [test6](/files/EDRs/test6.png) |
| 7    | ALE_AUTH_CONNECT_V4 | Lower                  | Same                 | CLEAR_ACTION_RIGHT | ALE_AUTH_CONNECT_V4 | Higher                | Same                | None       | Block  | [test7](/files/EDRs/test7.png) |
| 8    | ALE_AUTH_CONNECT_V4 | Higher                 | Same                 | CLEAR_ACTION_RIGHT | ALE_AUTH_CONNECT_V4 | Lower                 | Same                | CLEAR_ACTION_RIGHT | Permit | [test8](/files/EDRs/test8.png) |
| 9    | ALE_AUTH_CONNECT_V4 | Higher                 | Same                 | CLEAR_ACTION_RIGHT | OUTBOUND_IPPACKET_V4 | Lower                 | Same                | None       | Block  | [test9](/files/EDRs/test9.png) |
| 10   | ALE_AUTH_CONNECT_V4 | Higher                 | Same                 | CLEAR_ACTION_RIGHT | OUTBOUND_TRANSPORT_V4 | Lower                 | Same                | None       | Block  | [test10](/files/EDRs/test10.png) |
| 11   | ALE_AUTH_CONNECT_V4 | Higher                 | Same                 | None        | ALE_RESOURCE_ASSIGNMENT_V4 | Lower                 | Same                | None       | Block  | [test11](/files/EDRs/test11.png) |
| 12   | ALE_AUTH_CONNECT_V4 | Higher                 | Same                 | None        | ALE_FLOW_ESTABLISHED_V4 | Lower                 | Same                | None       | Block  | [test12](/files/EDRs/test12.png) |
| 13   | All Layers          | Higher                 | Same                 | None        | All Layers          | Lower                 | Same                | None       | Permit | [test13](/files/EDRs/test13.png) |

### Arbitration Principles

My tests revealed these WFP arbitration rules:

- **Same Layer, Same Sublayer**: A block filter overrides a permit filter if filter weights are equal (Case 1). A higher-weighted permit filter takes precedence (Case 2). `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` doesn’t guarantee a permit unless weights differ (Case 3).
- **Same Layer, Different Sublayers**: Higher-weighted sublayers are evaluated first. Blocks in lower-weighted sublayers can override permits unless the permit uses `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` (Cases 4–8).

By applying block filters at `FWPM_LAYER_OUTBOUND_TRANSPORT_V4` and `FWPM_LAYER_OUTBOUND_TRANSPORT_V6` targeting EDR_A’s remote IPs, I successfully disrupted EDR_A’s cloud connectivity, as these filters executed before EDR_A’s permit filters.  
  ![bypass](/files/EDRs/bypass.png)  

The BOF used to enumerate WFP filter and sublayer can be found [here](https://github.com/CUHKJason/WFPEnum), and a code snippet of creating custom sublayer can be found [here](https://github.com/CUHKJason/EDRSilencer-BOF_demo).

## Recommendations for EDR Vendors
To safeguard EDR telemetry against WFP-based attacks, vendors should adopt these strategies:

- **Custom Sublayer with Maximum Weight**: Create a sublayer with the highest possible weight (i.e., `0xFFFF`) to ensure it is evaluated first within its layer. This ensures EDR filters are prioritized over other sublayers within the same layer.
- **Hard Permit Filters**: Use `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` in permit filters to guarantee EDR traffic is allowed, overriding lower-weighted sublayer blocks within the same layer.
- **Multi-Layer Protection**: Deploy permit filters across multiple layers (e.g., `FWPM_LAYER_OUTBOUND_TRANSPORT_V4`, `FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4`, `FWPM_LAYER_ALE_AUTH_CONNECT_V4`) with `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`. This ensures EDR traffic is permitted at various stages of the network stack, mitigating the risk of early-layer block filters (e.g., `FWPM_LAYER_OUTBOUND_IPPACKET_V4`) or later-layer block filters (e.g., `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4`).

## Credit
All the above implementations cannot be done without the help from their research:
- [@netero_1010](https://x.com/netero_1010) for EDRSilencer and invaluable discussions.
- [Aon Cyber Labs](https://github.com/AonCyberLabs) for their EDRSilencer-BOF implementation.

## Resources
- [EDRSilencer GitHub](https://github.com/netero1010/EDRSilencer)
- [Aon Cyber Labs EDRSilencer-BOF](https://github.com/AonCyberLabs/EDRSilencer-BOF)
- [WFPExplorer](https://github.com/zodiacon/WFPExplorer)
