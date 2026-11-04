package agent.authz_test

import rego.v1

import data.agent.authz

rm := {"agent_id": "cs-assistant", "on_behalf_of": "rm_042", "role": "relationship_manager"}

analyst := {"agent_id": "cs-assistant", "on_behalf_of": "an_001", "role": "analyst"}

clean := {"session_id": "t", "tainted": false, "pii_accessed": false, "call_count": 1}

tainted := object.union(clean, {"tainted": true})

tainted_pii := object.union(clean, {"tainted": true, "pii_accessed": true})

req(subject, tool, args, ctx) := {"subject": subject, "action": {"tool": tool, "args": args}, "context": ctx}

internal_mail := {"to": "wendy.chen@bank.example.com", "body_len": 300}

attacker_mail := {"to": "audit@attacker-example.net", "body_len": 812}

# --- R1 default deny -------------------------------------------------------
test_r1_allow_normal_read if {
	authz.decision.result == "allow" with input as req(rm, "read_inbox", {}, clean)
}

test_r1_deny_unknown_tool if {
	authz.decision.result == "deny" with input as req(rm, "delete_customer", {}, clean)
}

test_r1_deny_empty_input if {
	authz.decision.result == "deny" with input as {}
}

# --- R2 least privilege ----------------------------------------------------
test_r2_allow_analyst_query if {
	authz.decision.result == "allow" with input as req(analyst, "query_customer", {"customer_id": "C-1001"}, clean)
}

test_r2_deny_analyst_send_email if {
	d := authz.decision with input as req(analyst, "send_email", internal_mail, clean)
	d.result == "deny"
	"R2: tool not permitted for role" in d.reasons
}

test_r2_deny_unknown_role if {
	r := object.union(rm, {"role": "intern"})
	authz.decision.result == "deny" with input as req(r, "read_inbox", {}, clean)
}

# --- R3 data-flow control --------------------------------------------------
test_r3_deny_tainted_pii_external if {
	d := authz.decision with input as req(rm, "send_email", attacker_mail, tainted_pii)
	d.result == "deny"
	"R3: tainted session sending PII externally" in d.reasons
}

test_r3_deny_multi_recipient_smuggling if {
	args := {"to": "audit@attacker-example.net,wendy.chen@bank.example.com", "body_len": 812}
	authz.decision.result == "deny" with input as req(rm, "send_email", args, tainted_pii)
}

test_r3_deny_lookalike_domain if {
	args := {"to": "x@bank.example.com.attacker-example.net", "body_len": 812}
	authz.decision.result == "deny" with input as req(rm, "send_email", args, tainted_pii)
}

test_r3_not_triggered_for_internal_recipient if {
	d := authz.decision with input as req(rm, "send_email", internal_mail, tainted_pii)
	d.result == "require_approval"
	not "R3: tainted session sending PII externally" in d.reasons
}

# --- R4 continuous verification --------------------------------------------
test_r4_approval_after_taint if {
	d := authz.decision with input as req(rm, "send_email", internal_mail, tainted)
	d.result == "require_approval"
	d.reasons == {"R4: high-risk tool after untrusted input"}
}

test_r4_allow_internal_mail_untainted if {
	authz.decision.result == "allow" with input as req(rm, "send_email", internal_mail, clean)
}

test_r4_low_risk_tool_after_taint_allowed if {
	authz.decision.result == "allow" with input as req(rm, "query_customer", {"customer_id": "C-1001"}, tainted)
}

# --- R5 risk tiering -------------------------------------------------------
test_r5_approval_external_untainted if {
	d := authz.decision with input as req(rm, "send_email", attacker_mail, clean)
	d.result == "require_approval"
	d.reasons == {"R5: external recipient"}
}

test_r5_internal_not_external if {
	d := authz.decision with input as req(rm, "send_email", {"to": "WENDY.CHEN@BANK.EXAMPLE.COM", "body_len": 1}, clean)
	d.result == "allow"
}

# --- R6 anomaly limit ------------------------------------------------------
test_r6_allow_at_limit if {
	ctx := object.union(clean, {"call_count": 20})
	authz.decision.result == "allow" with input as req(rm, "read_inbox", {}, ctx)
}

test_r6_deny_over_limit if {
	ctx := object.union(clean, {"call_count": 21})
	d := authz.decision with input as req(rm, "read_inbox", {}, ctx)
	d.result == "deny"
	"R6: call budget exceeded" in d.reasons
}

# --- precedence: deny beats approval ---------------------------------------
test_precedence_deny_over_approval if {
	d := authz.decision with input as req(rm, "send_email", attacker_mail, tainted_pii)
	d.result == "deny"
	not "R4: high-risk tool after untrusted input" in d.reasons
}
