# Output-side policy (R7): what may leave in the agent's own final answer.
# The gateway finds which PII fields of this session appear in the text (by fingerprint) and asks here.
package agent.output

import rego.v1

policy_version := data.agent.authz.policy_version

well_formed if {
	is_array(input.output.pii_fields)
	is_boolean(input.context.tainted)
}

# R7 output DLP: after untrusted input, PII obtained in this session must not appear in the output.
# (An untainted session is the relationship manager's own request; showing them the data is the task.)
redact contains "R7: session PII in output after untrusted input" if {
	well_formed
	input.context.tainted
	count(input.output.pii_fields) > 0
}

# R8 semantic check (second layer, gateway/semantic.py): a model reviewed the already-redacted text.
# It only runs for sessions that read untrusted input and accessed PII; "disabled" means the deployment
# turned it off, which leaves R7 as the only output control.
semantic := object.get(input.output, "semantic", {"status": "disabled"})

withhold contains "R8: semantic check found PII disclosure after untrusted input" if {
	well_formed
	input.context.tainted
	semantic.status == "ok"
	semantic.discloses == true
}

withhold contains "R8: semantic check unavailable, fail closed" if {
	well_formed
	input.context.tainted
	input.context.pii_accessed
	semantic.status == "error"
}

# Precedence: withhold (whole draft held back) > redact (matched spans) > allow.
# Fail closed: malformed input or no matching rule means redact whatever was matched.
default decision := {"result": "redact", "reasons": {"R1: no rule allowed the output"}}

decision := {"result": "withhold", "reasons": withhold | redact} if count(withhold) > 0

decision := {"result": "redact", "reasons": redact} if {
	count(withhold) == 0
	count(redact) > 0
}

decision := {"result": "allow", "reasons": set()} if {
	well_formed
	count(withhold) == 0
	count(redact) == 0
}
