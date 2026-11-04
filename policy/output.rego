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

# Fail closed: malformed input or no matching rule means redact whatever was matched.
default decision := {"result": "redact", "reasons": {"R1: no rule allowed the output"}}

decision := {"result": "redact", "reasons": redact} if count(redact) > 0

decision := {"result": "allow", "reasons": set()} if {
	well_formed
	count(redact) == 0
}
