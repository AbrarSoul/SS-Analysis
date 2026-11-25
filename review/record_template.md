---
case_id: CASE-XXXX
reviewer: R1
date: YYYY-MM-DD
checklist_version: v1
blind_to_model_results: yes
A: 
B: 
C: 
D: 
E: 
F: 
G: 
H: 
I: 
J: 
decision: 
---
<!--
Allowed answers for A-J: Yes / No / Unsure
Allowed decisions: Keep / Keep with corrections / Exclude
The block above is read by agreement.py - keep its keys and spelling exactly.
-->

# Review — CASE-XXXX

| Field | Value |
|---|---|
| CVE / CWE | |
| Repo / changed file | |
| Language | |
| My own bug location (written BEFORE opening metadata.json) | |

## Evidence per check

| # | Check | Result | Evidence (what you did, what you saw) |
|---|---|---|---|
| A | Vulnerable file = real pre-fix code | | |
| B | Patched file + diff = real fix | | |
| C | Commit is the fix for this CVE | | |
| D | CWE correct | | |
| E | Real fix really fixes it (executed or reasoned?) | | |
| F | `vulnerable_lines` locate the bug | | |
| G | Representability label correct | | |
| H | Both reworded variants vulnerable, same way | | |
| I | Alternative fix safe | | |
| J | Benign look-alike safe and a real look-alike | | |

## Corrections proposed
<!-- One line each: file, what to change, why. Write "None" if none. -->

## Exclusion reason
<!-- Only if decision = Exclude. -->

## Test materials
<!-- Attack inputs used, harness location (review/harness/CASE-XXXX/), what counted as success. -->
