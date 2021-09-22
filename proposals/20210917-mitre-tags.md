# Add missing MITRE ATT&CK tags

## Summary
This is a proposal for adding missing MITRE ATT&CK tags to the existing Falco rules.

We put a spreasheet together with our proposal at https://docs.google.com/spreadsheets/d/1lK2luf4iuOHDJEZ9EGcv3DkuuHeyRJAfeBzQCu2AuUI that we opened up for discussion during the community calls ([1](https://hackmd.io/3qYPnZPUQLGKCzR14va_qg?view#2021-06-09), [2](https://hackmd.io/3qYPnZPUQLGKCzR14va_qg?view#2021-06-23), [3](https://hackmd.io/3qYPnZPUQLGKCzR14va_qg?view#2021-07-14), [4](https://hackmd.io/3qYPnZPUQLGKCzR14va_qg?view#2021-07-21), [5](https://hackmd.io/3qYPnZPUQLGKCzR14va_qg?view#2021-09-22)).

## Motivation
Existing MITRE ATT&CK tags are few and not too accurate so we are including new tags for Enterprise and for Containers. Tagging rules according to MITRE ATT&CK matrix is an important method of classification and will be useful for any user.

## Proposal
Please find the proposal in the following spreadsheet: https://docs.google.com/spreadsheets/d/1lK2luf4iuOHDJEZ9EGcv3DkuuHeyRJAfeBzQCu2AuUI

## Old tags / New tags comparison

Old Tags               | New Tags
---------------------- | --------
command_and_control    | mitre_TA0011_command_and_control
credential_access      | mitre_TA0006_credential_access
defense_evasion        | mitre_TA0005_defense_evasion
discovery              | mitre_TA0007_discovery
execution              | mitre_TA0002_execution
exfiltration           | mitre_TA0010_exfiltration
lateral_movement       | mitre_TA0008_lateral_movement
persistence            | mitre_TA0003_persistence
port_knocking          | mitre_T1205.001_port_knocking
privilege_escalation   | mitre_TA0004_privilege_escalation
remote_access_software | mitre_T1219_remote_access_software
remote_access_tools    | mitre_T1219_remote_access_software
remote_service         | mitre_T1021_remote_services

## References
[MITRE ATT&CK for Containers](https://attack.mitre.org/matrices/enterprise/containers)
