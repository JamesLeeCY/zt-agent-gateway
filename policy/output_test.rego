package agent.output_test

import rego.v1

import data.agent.output

rm := {"agent_id": "cs-assistant", "on_behalf_of": "rm_042", "role": "relationship_manager"}

ctx(tainted) := {"session_id": "t", "tainted": tainted, "pii_accessed": true, "call_count": 3}

req(tainted, fields) := {"subject": rm, "context": ctx(tainted), "output": {"pii_fields": fields, "length": 400}}

test_r7_redact_pii_after_untrusted_input if {
	d := output.decision with input as req(true, ["account_number", "national_id"])
	d.result == "redact"
	d.reasons == {"R7: session PII in output after untrusted input"}
}

test_r7_allow_clean_output_after_untrusted_input if {
	output.decision.result == "allow" with input as req(true, [])
}

test_r7_allow_pii_in_untainted_session if {
	output.decision.result == "allow" with input as req(false, ["phone"])
}

test_r7_malformed_input_fails_closed if {
	output.decision.result == "redact" with input as {}
}

test_r7_policy_version_shared if {
	output.policy_version == data.agent.authz.policy_version
}
