# The gateway's rules (R1-R7, R9-R12; R8 is the output check of the main gateway) for any AgentDojo suite described in data.agentdojo.suites.<name>
# (banking, slack, travel; workspace keeps its own policy/workspace.rego, which these rules generalise).
# Same structure as policy/authz.rego: deny > require_approval > allow, default deny.
#
# input.suite      which suite's tool mapping to use; an unknown suite matches no known tool (deny)
# input.action     {"tool": ..., "args": {...}}
# input.context    tainted, pii_accessed, call_count, user_named_recipients (addresses in the user's request)
#                  and user_request (the request itself, lower case). Tool output can add to neither.
#                  links: web addresses in messages that tools returned, with the tool and the sender.
package agentdojo.gateway

import rego.v1

policy_version := "2026-11-15.1"

cfg := data.agentdojo.suites[input.suite]

max_calls_per_session := 40

as_list(v) := v if is_array(v)

as_list(v) := [v] if is_string(v)

# Destinations are compared in one form: lower case, no spaces; a URL by its host name only.
norm("url", x) := host if {
	s := trim_prefix(trim_prefix(lower(trim_space(x)), "https://"), "http://")
	host := split(trim_prefix(s, "www."), "/")[0]
}

norm(kind, x) := lower(replace(trim_space(x), " ", "")) if kind != "url"

# [kind, destination] for every place this call sends data, money or access to.
recipients contains [kind, norm(kind, x)] if {
	some arg, kind in cfg.egress[input.action.tool]
	some x in as_list(object.get(input.action.args, arg, []))
	is_string(x)
}

in_directory(kind, r) if r in cfg.internal[kind]

malformed("email", r) if not regex.match(`^[^@\s,;<>]+@[^@\s,;<>]+$`, r)

# Written by the user: listed in user_named_recipients, or (4+ characters) part of the request text.
user_named(r) if r in {lower(x) | some x in object.get(input.context, "user_named_recipients", [])}

user_named(r) if {
	count(r) >= 4
	contains(object.get(input.context, "user_request", ""), r)
}

external_recipient if {
	some [kind, r] in recipients
	not in_directory(kind, r)
}

external_recipient if {
	some [kind, r] in recipients
	malformed(kind, r)
}

# An external destination the user did not name. Only this kind can trigger R3.
unvouched_external_recipient if {
	some [kind, r] in recipients
	not in_directory(kind, r)
	not user_named(r)
}

unvouched_external_recipient if {
	some [kind, r] in recipients
	malformed(kind, r)
}

# A security setting (e.g. a password) set to a value that is not in the user's request.
untold_security_value if {
	some arg in cfg.user_supplied[input.action.tool]
	v := object.get(input.action.args, arg, "")
	not user_named(lower(trim_space(sprintf("%v", [v]))))
}

default recipient_class := "none"

recipient_class := "external" if external_recipient

recipient_class := "internal_directory" if {
	count(recipients) > 0
	not external_recipient
}

# A positive helper: with an unknown suite cfg is undefined, and a negated expression over it would not fire.
tool_known if input.action.tool in cfg.known_tools

deny contains "R2: unknown tool" if not tool_known

# A destination the user named is still external: R5 sends it to approval instead of denying it.
deny contains "R3: tainted session sending data externally" if {
	input.context.tainted
	input.context.pii_accessed
	unvouched_external_recipient
}

deny contains "R6: call budget exceeded" if input.context.call_count > max_calls_per_session

deny contains "R7: security setting changed to a value the user did not give" if {
	input.context.tainted
	untold_security_value
}

# Money, access or credentials handed to someone the user did not name is harm in itself: unlike R3 it does
# not wait until private data has been read (a transfer to the attacker after reading a product review).
# If the user named the destination in any form (e.g. "invite Dora", with her address from her web site),
# the user asked for this grant: it goes to approval (R4/R5) instead, where the reviewer sees the address.
deny contains "R9: tainted session moving money or access externally" if {
	input.context.tainted
	input.action.tool in cfg.value_tools
	unvouched_external_recipient
	not user_named_destination
}

user_named_destination if {
	some [_, r] in recipients
	user_named(r)
}

# Turning a protection off (two-factor authentication, a door lock) has no new value R7 could compare,
# so after untrusted input it is denied outright; the user can still do it outside the agent.
deny contains "R10: protection lowered after untrusted input" if {
	input.context.tainted
	input.action.tool in cfg.protection_lowering_tools
}

# Web addresses. Untrusted input can plant a link; the agent then opens it (a tracking or exploit page, or a
# URL that carries data in its path) or passes it on (phishing an internal colleague, who trusts a message
# that comes from the user). A link is vouched for when the user wrote it, or when a workspace member sent
# it in a message (an authenticated colleague; a web page or a message from an outsider has no such author).
# Off that list, R11 refuses to open it and R12 refuses to send it on, both only after untrusted input.
# Domain-like words count as links only with one of these endings, so a file name like report.pdf does not.
link_pattern := `(https?://)?([a-z0-9-]+\.)+(com|org|net|io|co|ai|app|dev|info|biz|ly|me|xyz|site|online|link|page|uk|de|ch|tw)(/[^\s)\]'"]*)?`

email_pattern := `[a-z0-9_.+-]+@[a-z0-9-]+(\.[a-z0-9-]+)+`

link_hosts(text) := {norm("url", m) | some m in regex.find_n(link_pattern, regex.replace(lower(text), email_pattern, ""), -1)}

vouched_host(h) if user_named(h)

vouched_host(h) if {
	some l in object.get(input.context, "links", [])
	l.tool in object.get(cfg, "member_authored_tools", set())
	lower(l.author) in cfg.internal.user
	norm("url", l.url) == h
}

deny contains "R11: tainted session opening a link nobody trusted gave" if {
	input.context.tainted
	some tool, arg in object.get(cfg, "browse_tools", {})
	tool == input.action.tool
	v := object.get(input.action.args, arg, "")
	is_string(v)
	not vouched_host(norm("url", v))
}

deny contains "R12: tainted session passing on a link nobody trusted gave" if {
	input.context.tainted
	some arg in object.get(object.get(cfg, "message_body", {}), input.action.tool, [])
	v := object.get(input.action.args, arg, "")
	is_string(v)
	some h in link_hosts(v)
	not vouched_host(h)
}

approval contains "R4: high-risk tool after untrusted input" if {
	input.context.tainted
	input.action.tool in cfg.high_risk_tools
}

approval contains "R5: recipient not in internal directory" if external_recipient

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
