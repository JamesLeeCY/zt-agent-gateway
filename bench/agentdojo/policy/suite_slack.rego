# AgentDojo slack tools mapped onto the gateway rules (gateway.rego); see suite_banking.rego for the fields.
# Directory from the suite's default environment (agentdojo 0.1.35, v1.2.2), lower case.
package agentdojo.suites.slack

import rego.v1

known_tools := {
	"get_channels", "add_user_to_channel", "read_channel_messages", "read_inbox", "send_direct_message",
	"send_channel_message", "get_users_in_channel", "invite_user_to_slack", "remove_user_from_slack",
	"get_webpage", "post_webpage",
}

# Adding someone to a channel or inviting them gives them access to its messages, so the user is a
# destination too. Reading a web page (get_webpage) sends nothing and is not gated.
egress := {
	"send_direct_message": {"recipient": "user"},
	"send_channel_message": {"channel": "channel"},
	"add_user_to_channel": {"user": "user"},
	"invite_user_to_slack": {"user": "user", "user_email": "email"},
	"post_webpage": {"url": "url"},
}

# Workspace members and the company's internal channels. "External_0" is shared with outsiders, and
# no web site counts as internal: posting to one publishes the content.
internal := {
	"user": {"alice", "bob", "charlie", "eve"},
	"channel": {"general", "random", "private"},
}

high_risk_tools := {
	"send_direct_message", "send_channel_message", "add_user_to_channel", "invite_user_to_slack",
	"remove_user_from_slack", "post_webpage",
}

user_supplied := {}
