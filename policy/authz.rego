# Zero-trust authorization policy for the customer-service agent (PDP).
# Precedence: deny > require_approval > allow. Anything not explicitly allowed is denied (R1).
package agent.authz

import rego.v1

policy_version := "2026-11-05.1"

high_risk_tools := {"send_email"}

internal_domain := "bank.example.com"

role_tools := {
	"relationship_manager": {"read_inbox", "query_customer", "send_email"},
	"analyst": {"query_customer"},
}

max_calls_per_session := 20

recipient := trim_space(lower(input.action.args.to))

# Exactly one well-formed address. "a@evil.net,b@bank.example.com" is not one address.
single_address if regex.match(`^[^@\s,;<>]+@[^@\s,;<>]+$`, recipient)

# Internal = listed in the directory (allowlist), not merely "ends with the bank's domain":
# an unlisted mailbox on our domain may be a relay that auto-forwards outside.
internal_recipient if {
	single_address
	recipient in data.agent.directory.internal_mailboxes
}

# For the human reviewer and the audit trail: what kind of recipient is this?
default recipient_class := "none"

recipient_class := "internal_directory" if internal_recipient

recipient_class := "internal_domain_unlisted" if {
	not internal_recipient
	single_address
	endswith(recipient, concat("", ["@", internal_domain]))
}

recipient_class := "external" if {
	input.action.tool == "send_email"
	not internal_recipient
	not endswith(recipient, concat("", ["@", internal_domain]))
}

recipient_class := "malformed" if {
	input.action.tool == "send_email"
	not single_address
	endswith(recipient, concat("", ["@", internal_domain]))
}

external_recipient if {
	input.action.tool == "send_email"
	not internal_recipient
}

# R2 least privilege: the role must be explicitly granted the tool (unknown roles get nothing).
tool_permitted if input.action.tool in role_tools[input.subject.role]

deny contains "R2: tool not permitted for role" if not tool_permitted

# R3 data-flow control: untrusted input + PII in the session + external recipient = exfiltration path.
deny contains "R3: tainted session sending PII externally" if {
	input.context.tainted
	input.context.pii_accessed
	external_recipient
}

# R6 anomaly limit.
deny contains "R6: call budget exceeded" if {
	input.context.call_count > max_calls_per_session
}

# R4 continuous verification: after reading untrusted content, high-risk actions need a human.
approval contains "R4: high-risk tool after untrusted input" if {
	input.context.tainted
	input.action.tool in high_risk_tools
}

# R5 risk tiering: any external recipient needs a human.
approval contains "R5: recipient not in internal directory" if external_recipient

# R1 default deny (also enforced by the gateway when no decision comes back).
default decision := {"result": "deny", "reasons": {"R1: no rule allowed the request"}}

decision := {"result": "deny", "reasons": deny} if count(deny) > 0

decision := {"result": "require_approval", "reasons": approval} if {
	count(deny) == 0
	count(approval) > 0
}

decision := {"result": "allow", "reasons": set()} if {
	count(deny) == 0
	count(approval) == 0
}
