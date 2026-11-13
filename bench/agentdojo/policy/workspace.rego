# The gateway's rules (R1-R6) mapped onto the AgentDojo "workspace" tools (email, calendar, cloud drive).
# Same structure as policy/authz.rego: deny > require_approval > allow, default deny.
package agentdojo.workspace

import rego.v1

policy_version := "2026-11-10.1"

# Every tool of the suite. Anything else is denied (R1/R2).
known_tools := {
	"send_email", "delete_email", "get_unread_emails", "get_sent_emails", "get_received_emails",
	"get_draft_emails", "search_emails", "search_contacts_by_name", "search_contacts_by_email",
	"get_current_day", "search_calendar_events", "get_day_calendar_events", "create_calendar_event",
	"cancel_calendar_event", "reschedule_calendar_event", "add_calendar_event_participants",
	"append_to_file", "search_files_by_filename", "create_file", "delete_file", "get_file_by_id",
	"list_files", "share_file", "search_files",
}

# Tools that send data to other people, and the arguments that hold the recipients.
egress_args := {
	"send_email": ["recipients", "cc", "bcc"],
	"share_file": ["email"],
	"create_calendar_event": ["participants"],
	"add_calendar_event_participants": ["participants"],
}

# Irreversible or outward-facing actions.
high_risk_tools := {
	"send_email", "share_file", "create_calendar_event", "add_calendar_event_participants",
	"delete_email", "delete_file", "cancel_calendar_event",
}

max_calls_per_session := 40

as_list(v) := v if is_array(v)

as_list(v) := [v] if is_string(v)

recipients contains r if {
	some arg in egress_args[input.action.tool]
	some x in as_list(object.get(input.action.args, arg, []))
	r := trim_space(lower(x))
}

well_formed(r) if regex.match(`^[^@\s,;<>]+@[^@\s,;<>]+$`, r)

# Internal = listed in the employee directory. A look-alike domain or a malformed address is external.
external_recipient if {
	some r in recipients
	not r in data.agentdojo.directory.internal_mailboxes
}

external_recipient if {
	some r in recipients
	not well_formed(r)
}

# Named by the user: the address is written in the user's own request (context.user_named_recipients).
# Injected text arrives through tool output and cannot put an address on that list.
user_named(r) if r in {lower(x) | some x in object.get(input.context, "user_named_recipients", [])}

# An external recipient the user did not name. Only this kind can trigger R3.
unvouched_external_recipient if {
	some r in recipients
	not r in data.agentdojo.directory.internal_mailboxes
	not user_named(r)
}

unvouched_external_recipient if {
	some r in recipients
	not well_formed(r)
}

default recipient_class := "none"

recipient_class := "external" if external_recipient

recipient_class := "internal_directory" if {
	count(recipients) > 0
	not external_recipient
}

deny contains "R2: unknown tool" if not input.action.tool in known_tools

# A recipient the user named is still external: R5 sends it to approval instead of denying it.
deny contains "R3: tainted session sending data externally" if {
	input.context.tainted
	input.context.pii_accessed
	unvouched_external_recipient
}

deny contains "R6: call budget exceeded" if input.context.call_count > max_calls_per_session

approval contains "R4: high-risk tool after untrusted input" if {
	input.context.tainted
	input.action.tool in high_risk_tools
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
