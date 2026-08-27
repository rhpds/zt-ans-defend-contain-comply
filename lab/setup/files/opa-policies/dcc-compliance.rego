package dcc.compliance

import rego.v1

# System compliance baselines for the DCC workshop.
# Input: JSON object with host facts collected by the compliance-audit playbook.
# Numeric facts are coerced with to_number() because Ansible JSON-encodes
# them as strings.

default compliant := false
default selinux_enforcing := false
default firewall_active := false
default ssh_root_login_disabled := false
default ssh_x11_forwarding_disabled := false
default ssh_max_auth_tries_ok := false
default ssh_client_alive_set := false
default ssh_banner_set := false
default sysctl_accept_redirects_disabled := false
default sysctl_send_redirects_disabled := false
default sysctl_aslr_enabled := false
default sysctl_source_route_disabled := false
default passwd_permissions_ok := false
default shadow_permissions_ok := false
default sshd_config_permissions_ok := false
default no_unnecessary_services := false
default umask_ok := false
default no_open_cves := false

truthy(val) if {
	val == true
}

truthy(val) if {
	lower(sprintf("%v", [val])) == "true"
}

# ── SELinux ─────────────────────────────────────────────────────────

selinux_enforcing if {
	input.selinux_mode == "Enforcing"
}

# ── Firewall ────────────────────────────────────────────────────────

firewall_active if {
	truthy(input.firewall_active)
}

# ── SSH Hardening ───────────────────────────────────────────────────

ssh_root_login_disabled if {
	input.ssh_permit_root_login == "no"
}

ssh_x11_forwarding_disabled if {
	input.ssh_x11_forwarding == "no"
}

ssh_max_auth_tries_ok if {
	to_number(input.ssh_max_auth_tries) <= 4
}

ssh_client_alive_set if {
	interval := to_number(input.ssh_client_alive_interval)
	interval > 0
	interval <= 300
}

ssh_banner_set if {
	input.ssh_banner != "none"
	input.ssh_banner != ""
}

# ── Kernel Parameters ───────────────────────────────────────────────

sysctl_accept_redirects_disabled if {
	to_number(input.sysctl_accept_redirects) == 0
}

sysctl_send_redirects_disabled if {
	to_number(input.sysctl_send_redirects) == 0
}

sysctl_aslr_enabled if {
	to_number(input.sysctl_randomize_va_space) == 2
}

sysctl_source_route_disabled if {
	to_number(input.sysctl_accept_source_route) == 0
}

# ── File Permissions ────────────────────────────────────────────────
# Modes are the last three octal digits (e.g. 644), not decimal-from-octal.

passwd_permissions_ok if {
	to_number(input.passwd_mode) <= 644
}

shadow_permissions_ok if {
	to_number(input.shadow_mode) <= 640
}

sshd_config_permissions_ok if {
	to_number(input.sshd_config_mode) <= 600
}

# ── Services ────────────────────────────────────────────────────────

no_unnecessary_services if {
	not truthy(input.rpcbind_enabled)
}

# ── Login ───────────────────────────────────────────────────────────

umask_ok if {
	to_number(input.umask) == 27
}

# ── Vulnerability State ─────────────────────────────────────────────

no_open_cves if {
	count(input.open_cves) == 0
}

# ── Control Definitions ─────────────────────────────────────────────

controls := [
	{"id": "SEL-01", "name": "SELinux enforcing", "category": "selinux", "pass": selinux_enforcing},
	{"id": "FW-01", "name": "Firewall active", "category": "firewall", "pass": firewall_active},
	{"id": "SSH-01", "name": "Root login disabled", "category": "ssh", "pass": ssh_root_login_disabled},
	{"id": "SSH-02", "name": "X11 forwarding disabled", "category": "ssh", "pass": ssh_x11_forwarding_disabled},
	{"id": "SSH-03", "name": "Max auth tries <= 4", "category": "ssh", "pass": ssh_max_auth_tries_ok},
	{"id": "SSH-04", "name": "Client alive interval set", "category": "ssh", "pass": ssh_client_alive_set},
	{"id": "SSH-05", "name": "SSH login banner configured", "category": "ssh", "pass": ssh_banner_set},
	{"id": "KERN-01", "name": "ICMP redirects disabled", "category": "kernel", "pass": sysctl_accept_redirects_disabled},
	{"id": "KERN-02", "name": "Send redirects disabled", "category": "kernel", "pass": sysctl_send_redirects_disabled},
	{"id": "KERN-03", "name": "ASLR enabled", "category": "kernel", "pass": sysctl_aslr_enabled},
	{"id": "KERN-04", "name": "Source routing disabled", "category": "kernel", "pass": sysctl_source_route_disabled},
	{"id": "FILE-01", "name": "/etc/passwd permissions <= 644", "category": "files", "pass": passwd_permissions_ok},
	{"id": "FILE-02", "name": "/etc/shadow permissions <= 640", "category": "files", "pass": shadow_permissions_ok},
	{"id": "FILE-03", "name": "sshd_config permissions <= 600", "category": "files", "pass": sshd_config_permissions_ok},
	{"id": "SVC-01", "name": "No unnecessary services (rpcbind)", "category": "services", "pass": no_unnecessary_services},
	{"id": "LOGIN-01", "name": "UMASK 027 in login.defs", "category": "login", "pass": umask_ok},
	{"id": "CVE-01", "name": "No open CVEs", "category": "vulnerability", "pass": no_open_cves},
]

passed_controls := [c | some c in controls; c.pass == true]
failed_controls := [c | some c in controls; c.pass == false]

compliant if {
	count(failed_controls) == 0
}

result := {
	"compliant": compliant,
	"controls": controls,
	"total": count(controls),
	"passed": count(passed_controls),
	"failed": count(failed_controls),
}
