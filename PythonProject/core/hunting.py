from typing import List
from uuid import uuid5, NAMESPACE_DNS

import streamlit as st


def normalize_ips(ips: List[str]) -> List[str]:
    clean_ips = []

    for ip in ips:
        value = str(ip).strip()

        if value and value not in clean_ips:
            clean_ips.append(value)

    return sorted(clean_ips)


def quote_double(ips: List[str]) -> str:
    return ", ".join([f'"{ip}"' for ip in ips])


def quote_single(ips: List[str]) -> str:
    return ", ".join([f"'{ip}'" for ip in ips])


def space_separated(ips: List[str]) -> str:
    return " ".join(ips)


def render_artifact_download(
    label: str,
    content: str,
    file_name: str,
    key: str,
) -> None:
    st.download_button(
        label=label,
        data=content.encode("utf-8"),
        file_name=file_name,
        mime="text/plain",
        use_container_width=True,
        key=key,
    )


# =========================
# MORE SIEM QUERIES
# =========================

def build_splunk_query(ips: List[str]) -> str:
    ip_list = quote_double(ips)

    return f"""index=*
(
    src_ip IN ({ip_list})
    OR dest_ip IN ({ip_list})
    OR source_ip IN ({ip_list})
    OR destination_ip IN ({ip_list})
    OR client_ip IN ({ip_list})
    OR remote_ip IN ({ip_list})
)
| eval matched_ip=coalesce(src_ip, dest_ip, source_ip, destination_ip, client_ip, remote_ip)
| stats count min(_time) as first_seen max(_time) as last_seen values(index) as indexes values(sourcetype) as sourcetypes by matched_ip
| convert ctime(first_seen) ctime(last_seen)
| sort - count"""


def build_sentinel_commonsecuritylog_query(ips: List[str]) -> str:
    ip_list = quote_double(ips)

    return f"""let malicious_ips = dynamic([{ip_list}]);
CommonSecurityLog
| where SourceIP in (malicious_ips)
    or DestinationIP in (malicious_ips)
    or DeviceCustomIPv6Address1 in (malicious_ips)
| summarize EventCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
    by SourceIP, DestinationIP, DeviceVendor, DeviceProduct, Activity
| order by EventCount desc"""


def build_sentinel_mde_query(ips: List[str]) -> str:
    ip_list = quote_double(ips)

    return f"""let malicious_ips = dynamic([{ip_list}]);
DeviceNetworkEvents
| where RemoteIP in (malicious_ips)
    or LocalIP in (malicious_ips)
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          LocalIP, RemoteIP, RemotePort, Protocol, ActionType
| summarize EventCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, ActionType
| order by EventCount desc"""


def build_qradar_query(ips: List[str]) -> str:
    ip_list = quote_single(ips)

    return f"""SELECT
    sourceip,
    destinationip,
    QIDNAME(qid) AS event_name,
    LOGSOURCENAME(logsourceid) AS log_source,
    COUNT(*) AS event_count
FROM events
WHERE sourceip IN ({ip_list})
   OR destinationip IN ({ip_list})
GROUP BY sourceip, destinationip, qid, logsourceid
ORDER BY event_count DESC
LAST 24 HOURS"""


def build_elastic_query(ips: List[str]) -> str:
    ip_list = quote_double(ips)

    return f"""source.ip:({ip_list})
OR destination.ip:({ip_list})
OR client.ip:({ip_list})
OR server.ip:({ip_list})
OR host.ip:({ip_list})"""


def build_wazuh_query(ips: List[str]) -> str:
    ip_list = quote_double(ips)

    return f"""data.srcip:({ip_list})
OR data.dstip:({ip_list})
OR data.src_ip:({ip_list})
OR data.dest_ip:({ip_list})
OR agent.ip:({ip_list})"""


def build_graylog_query(ips: List[str]) -> str:
    ip_list = " OR ".join(
        [
            f'src_ip:"{ip}" OR dst_ip:"{ip}" OR source_ip:"{ip}" OR destination_ip:"{ip}"'
            for ip in ips
        ]
    )

    return f"""({ip_list})"""


def build_chronicle_query(ips: List[str]) -> str:
    ip_list = quote_double(ips)

    return f"""metadata.event_type = "NETWORK_CONNECTION"
(
    principal.ip IN ({ip_list})
    OR target.ip IN ({ip_list})
    OR src.ip IN ({ip_list})
    OR dst.ip IN ({ip_list})
)"""


def build_sumo_query(ips: List[str]) -> str:
    conditions = " OR ".join([f'"{ip}"' for ip in ips])

    return f"""({conditions})
| where src_ip in ({quote_double(ips)})
    or dest_ip in ({quote_double(ips)})
    or source_ip in ({quote_double(ips)})
    or destination_ip in ({quote_double(ips)})
| count by src_ip, dest_ip, source_ip, destination_ip"""


def render_more_siem_queries(ips: List[str]) -> None:
    st.subheader("More SIEM Queries")

    tabs = st.tabs(
        [
            "Splunk",
            "Sentinel Firewall",
            "Sentinel MDE",
            "QRadar",
            "Elastic",
            "Wazuh",
            "Graylog",
            "Chronicle",
            "Sumo Logic",
        ]
    )

    siem_artifacts = {
        "splunk_spl.txt": build_splunk_query(ips),
        "sentinel_commonsecuritylog.kql": build_sentinel_commonsecuritylog_query(ips),
        "sentinel_mde.kql": build_sentinel_mde_query(ips),
        "qradar_aql.sql": build_qradar_query(ips),
        "elastic_kql.txt": build_elastic_query(ips),
        "wazuh_query.txt": build_wazuh_query(ips),
        "graylog_query.txt": build_graylog_query(ips),
        "chronicle_udm.txt": build_chronicle_query(ips),
        "sumologic_query.txt": build_sumo_query(ips),
    }

    with tabs[0]:
        st.code(siem_artifacts["splunk_spl.txt"], language="text")

    with tabs[1]:
        st.code(siem_artifacts["sentinel_commonsecuritylog.kql"], language="text")

    with tabs[2]:
        st.code(siem_artifacts["sentinel_mde.kql"], language="text")

    with tabs[3]:
        st.code(siem_artifacts["qradar_aql.sql"], language="sql")

    with tabs[4]:
        st.code(siem_artifacts["elastic_kql.txt"], language="text")

    with tabs[5]:
        st.code(siem_artifacts["wazuh_query.txt"], language="text")

    with tabs[6]:
        st.code(siem_artifacts["graylog_query.txt"], language="text")

    with tabs[7]:
        st.code(siem_artifacts["chronicle_udm.txt"], language="text")

    with tabs[8]:
        st.code(siem_artifacts["sumologic_query.txt"], language="text")

    bundle = "\n\n".join(
        [
            f"### {file_name}\n{content}"
            for file_name, content in siem_artifacts.items()
        ]
    )

    render_artifact_download(
        label="Download SIEM Query Bundle",
        content=bundle,
        file_name="siem_hunting_queries.txt",
        key="download_siem_bundle",
    )


# =========================
# SIGMA RULE GENERATOR
# =========================

def build_sigma_rule(ips: List[str]) -> str:
    rule_id = uuid5(
        NAMESPACE_DNS,
        "soc-toolkit-malicious-ip-" + ",".join(ips),
    )

    yaml_ips = "\n".join([f"      - {ip}" for ip in ips])

    return f"""title: Malicious IP Communication Detected
id: {rule_id}
status: experimental
description: Detects network communication involving IP addresses flagged as malicious by SOC Analyst Toolkit enrichment workflow.
author: kiki
date: 2026/07/05
references:
  - https://www.abuseipdb.com/
  - https://www.virustotal.com/
tags:
  - attack.command_and_control
  - attack.t1071
  - attack.exfiltration
logsource:
  category: network
detection:
  selection_source_ip:
    source.ip:
{yaml_ips}
  selection_destination_ip:
    destination.ip:
{yaml_ips}
  selection_src_ip_legacy:
    src_ip:
{yaml_ips}
  selection_dst_ip_legacy:
    dst_ip:
{yaml_ips}
  condition: selection_source_ip or selection_destination_ip or selection_src_ip_legacy or selection_dst_ip_legacy
fields:
  - source.ip
  - destination.ip
  - src_ip
  - dst_ip
  - user.name
  - host.name
  - process.name
  - event.action
falsepositives:
  - Security testing
  - Threat intelligence validation
  - Known vendor or partner infrastructure
  - Previously approved business connection
level: high
"""


def render_sigma_rule_generator(ips: List[str]) -> None:
    st.subheader("Sigma Rule Generator")

    sigma_rule = build_sigma_rule(ips)

    st.code(sigma_rule, language="yaml")

    render_artifact_download(
        label="Download Sigma Rule",
        content=sigma_rule,
        file_name="malicious_ip_communication_sigma.yml",
        key="download_sigma_rule",
    )


# =========================
# FIREWALL BLOCK RULE GENERATOR
# =========================

def ip_object_name(ip: str, prefix: str = "blk") -> str:
    return f"{prefix}_{ip.replace('.', '_').replace(':', '_')}"


def build_fortigate_rules(ips: List[str]) -> str:
    address_objects = []

    for ip in ips:
        name = ip_object_name(ip)
        address_objects.append(
            f"""edit "{name}"
    set subnet {ip} 255.255.255.255
next"""
        )

    members = " ".join([f'"{ip_object_name(ip)}"' for ip in ips])

    return f"""# FortiGate CLI
# Review interface names and policy order before applying.

config firewall address
{chr(10).join(address_objects)}
end

config firewall addrgrp
edit "SOC_Malicious_IP_Blocklist"
    set member {members}
next
end

config firewall policy
edit 0
    set name "Block_SOC_Malicious_IPs"
    set srcintf "any"
    set dstintf "any"
    set srcaddr "all"
    set dstaddr "SOC_Malicious_IP_Blocklist"
    set action deny
    set schedule "always"
    set service "ALL"
    set logtraffic all
next
end"""


def build_paloalto_rules(ips: List[str]) -> str:
    objects = "\n".join(
        [
            f"set address {ip_object_name(ip)} ip-netmask {ip}/32"
            for ip in ips
        ]
    )

    group_members = " ".join([ip_object_name(ip) for ip in ips])

    return f"""# Palo Alto PAN-OS CLI
# Review zones, rule order, and commit process before applying.

{objects}

set address-group SOC_Malicious_IP_Blocklist static [ {group_members} ]

set rulebase security rules Block_SOC_Malicious_IPs from any to any source any destination SOC_Malicious_IP_Blocklist application any service any action deny log-start yes log-end yes"""


def build_cisco_asa_rules(ips: List[str]) -> str:
    network_objects = "\n".join([f" network-object host {ip}" for ip in ips])

    return f"""! Cisco ASA
! Review interface name and ACL direction before applying.

object-group network SOC_MALICIOUS_IP_BLOCKLIST
{network_objects}

access-list OUTSIDE_IN extended deny ip any object-group SOC_MALICIOUS_IP_BLOCKLIST log
access-group OUTSIDE_IN in interface outside"""


def build_iptables_rules(ips: List[str]) -> str:
    lines = ["# Linux iptables", "# Review chain placement before applying."]

    for ip in ips:
        lines.append(f"iptables -A INPUT -s {ip} -j DROP")
        lines.append(f"iptables -A OUTPUT -d {ip} -j DROP")
        lines.append(f"iptables -A FORWARD -s {ip} -j DROP")
        lines.append(f"iptables -A FORWARD -d {ip} -j DROP")

    return "\n".join(lines)


def build_nftables_rules(ips: List[str]) -> str:
    ip_elements = ", ".join(ips)

    return f"""# Linux nftables
# Review table/chain names before applying.

nft add table inet soc_filter
nft add chain inet soc_filter input {{ type filter hook input priority 0 \\; }}
nft add chain inet soc_filter output {{ type filter hook output priority 0 \\; }}
nft add set inet soc_filter malicious_ips {{ type ipv4_addr \\; }}
nft add element inet soc_filter malicious_ips {{ {ip_elements} }}
nft add rule inet soc_filter input ip saddr @malicious_ips drop
nft add rule inet soc_filter output ip daddr @malicious_ips drop"""


def build_windows_firewall_rules(ips: List[str]) -> str:
    ip_list = ",".join(ips)

    return f"""# Windows Defender Firewall PowerShell
# Run as Administrator.

New-NetFirewallRule `
  -DisplayName "Block SOC Malicious IPs - Outbound" `
  -Direction Outbound `
  -RemoteAddress {ip_list} `
  -Action Block

New-NetFirewallRule `
  -DisplayName "Block SOC Malicious IPs - Inbound" `
  -Direction Inbound `
  -RemoteAddress {ip_list} `
  -Action Block"""


def build_cloudflare_waf_rule(ips: List[str]) -> str:
    ip_list = space_separated(ips)

    return f"""# Cloudflare WAF Custom Rule Expression
# Action recommendation: Block or Managed Challenge after validation.

(ip.src in {{{ip_list}}})"""


def render_firewall_block_rules(ips: List[str]) -> None:
    st.subheader("Firewall Block Rule Generator")

    st.caption(
        "Review rule order, interface/zone names, and business allowlist before applying any block rule."
    )

    firewall_artifacts = {
        "fortigate_block_rules.txt": build_fortigate_rules(ips),
        "palo_alto_block_rules.txt": build_paloalto_rules(ips),
        "cisco_asa_block_rules.txt": build_cisco_asa_rules(ips),
        "iptables_block_rules.sh": build_iptables_rules(ips),
        "nftables_block_rules.sh": build_nftables_rules(ips),
        "windows_firewall_block_rules.ps1": build_windows_firewall_rules(ips),
        "cloudflare_waf_rule.txt": build_cloudflare_waf_rule(ips),
    }

    tabs = st.tabs(
        [
            "FortiGate",
            "Palo Alto",
            "Cisco ASA",
            "iptables",
            "nftables",
            "Windows",
            "Cloudflare",
        ]
    )

    with tabs[0]:
        st.code(firewall_artifacts["fortigate_block_rules.txt"], language="text")

    with tabs[1]:
        st.code(firewall_artifacts["palo_alto_block_rules.txt"], language="text")

    with tabs[2]:
        st.code(firewall_artifacts["cisco_asa_block_rules.txt"], language="text")

    with tabs[3]:
        st.code(firewall_artifacts["iptables_block_rules.sh"], language="bash")

    with tabs[4]:
        st.code(firewall_artifacts["nftables_block_rules.sh"], language="bash")

    with tabs[5]:
        st.code(firewall_artifacts["windows_firewall_block_rules.ps1"], language="powershell")

    with tabs[6]:
        st.code(firewall_artifacts["cloudflare_waf_rule.txt"], language="text")

    bundle = "\n\n".join(
        [
            f"### {file_name}\n{content}"
            for file_name, content in firewall_artifacts.items()
        ]
    )

    render_artifact_download(
        label="Download Firewall Rule Bundle",
        content=bundle,
        file_name="firewall_block_rules_bundle.txt",
        key="download_firewall_bundle",
    )


# =========================
# EDR HUNTING QUERIES
# =========================

def build_mde_advanced_hunting(ips: List[str]) -> str:
    ip_list = quote_double(ips)

    return f"""let malicious_ips = dynamic([{ip_list}]);
DeviceNetworkEvents
| where RemoteIP in (malicious_ips)
    or LocalIP in (malicious_ips)
| project Timestamp, DeviceName, DeviceId, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          LocalIP, RemoteIP, RemotePort, Protocol, ActionType
| summarize EventCount=count(), FirstSeen=min(Timestamp), LastSeen=max(Timestamp)
    by DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName,
       RemoteIP, RemotePort, ActionType
| order by EventCount desc"""


def build_crowdstrike_logscale(ips: List[str]) -> str:
    conditions = " OR ".join([f'RemoteAddress="{ip}" OR LocalAddress="{ip}"' for ip in ips])

    return f"""# CrowdStrike Falcon LogScale
# Adjust index/repository and event field names based on your telemetry.

#event_simpleName=/NetworkConnectIP4|NetworkConnectIP6/
| where {conditions}
| groupBy([ComputerName, UserName, ImageFileName, RemoteAddress, RemotePort], function=count())
| sort(_count, order=desc)"""


def build_sentinelone_deep_visibility(ips: List[str]) -> str:
    conditions = " OR ".join(
        [
            f'DstIP = "{ip}" OR SrcIP = "{ip}" OR EndpointIp = "{ip}"'
            for ip in ips
        ]
    )

    return f"""// SentinelOne Deep Visibility
// Adjust field names if your tenant uses different schema.

EventType = "IP Connect"
AND ({conditions})"""


def build_carbon_black_query(ips: List[str]) -> str:
    conditions = " OR ".join(
        [
            f"netconn_remote_ip:{ip} OR netconn_local_ip:{ip}"
            for ip in ips
        ]
    )

    return f"""# VMware Carbon Black Cloud Investigate
# Use in Process Search / Investigate.

({conditions})"""


def build_elastic_endpoint_query(ips: List[str]) -> str:
    ip_list = quote_double(ips)

    return f"""event.category:network AND
(
    destination.ip:({ip_list})
    OR source.ip:({ip_list})
    OR client.ip:({ip_list})
    OR server.ip:({ip_list})
)"""


def build_osquery_query(ips: List[str]) -> str:
    ip_list = quote_single(ips)

    return f"""-- osquery
-- Shows active connections involving malicious IPs at query time.

SELECT
    p.pid,
    p.name,
    p.path,
    p.cmdline,
    l.address AS local_address,
    l.port AS local_port,
    r.address AS remote_address,
    r.port AS remote_port,
    s.state
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
LEFT JOIN listening_ports l ON s.pid = l.pid
LEFT JOIN process_open_sockets r ON s.pid = r.pid
WHERE r.address IN ({ip_list})
   OR l.address IN ({ip_list});"""


def render_edr_hunting_queries(ips: List[str]) -> None:
    st.subheader("EDR Hunting Queries")

    edr_artifacts = {
        "microsoft_defender_advanced_hunting.kql": build_mde_advanced_hunting(ips),
        "crowdstrike_logscale.txt": build_crowdstrike_logscale(ips),
        "sentinelone_deep_visibility.txt": build_sentinelone_deep_visibility(ips),
        "carbon_black_query.txt": build_carbon_black_query(ips),
        "elastic_endpoint_query.txt": build_elastic_endpoint_query(ips),
        "osquery_active_connections.sql": build_osquery_query(ips),
    }

    tabs = st.tabs(
        [
            "MDE",
            "CrowdStrike",
            "SentinelOne",
            "Carbon Black",
            "Elastic Endpoint",
            "osquery",
        ]
    )

    with tabs[0]:
        st.code(edr_artifacts["microsoft_defender_advanced_hunting.kql"], language="text")

    with tabs[1]:
        st.code(edr_artifacts["crowdstrike_logscale.txt"], language="text")

    with tabs[2]:
        st.code(edr_artifacts["sentinelone_deep_visibility.txt"], language="text")

    with tabs[3]:
        st.code(edr_artifacts["carbon_black_query.txt"], language="text")

    with tabs[4]:
        st.code(edr_artifacts["elastic_endpoint_query.txt"], language="text")

    with tabs[5]:
        st.code(edr_artifacts["osquery_active_connections.sql"], language="sql")

    bundle = "\n\n".join(
        [
            f"### {file_name}\n{content}"
            for file_name, content in edr_artifacts.items()
        ]
    )

    render_artifact_download(
        label="Download EDR Hunting Bundle",
        content=bundle,
        file_name="edr_hunting_queries_bundle.txt",
        key="download_edr_bundle",
    )


# =========================
# MAIN RENDERER
# =========================

def render_security_artifacts(malicious_ips: List[str]) -> None:
    ips = normalize_ips(malicious_ips)

    if not ips:
        return

    st.divider()
    st.header("Detection & Response Artifacts")

    st.caption(
        "Generated artifacts are investigation accelerators. Validate against internal telemetry, "
        "allowlists, business context, and change-control process before enforcement."
    )

    tab_siem, tab_sigma, tab_firewall, tab_edr = st.tabs(
        [
            "SIEM Queries",
            "Sigma Rule",
            "Firewall Block Rules",
            "EDR Hunting",
        ]
    )

    with tab_siem:
        render_more_siem_queries(ips)

    with tab_sigma:
        render_sigma_rule_generator(ips)

    with tab_firewall:
        render_firewall_block_rules(ips)

    with tab_edr:
        render_edr_hunting_queries(ips)
