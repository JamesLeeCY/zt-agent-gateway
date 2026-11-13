# AgentDojo banking tools mapped onto the gateway rules (gateway.rego).
# Directories are taken from each suite's default environment (agentdojo 0.1.35, v1.2.2), lower case.
#
#   known_tools      every tool of the suite (anything else: R2)
#   egress           tool -> {argument: destination kind}: where a call sends data, money or access
#   internal         destination kind -> destinations that count as internal (the directory)
#   high_risk_tools  irreversible or outward-facing actions (R4 after untrusted input)
#   user_supplied    tool -> arguments whose value must come from the user's request once tainted (R7)
#
# The tools that make a session tainted (return content other people wrote) or mark PII as accessed are
# listed next to the context code, in gateway_defense.py.

package agentdojo.suites.banking

import rego.v1

known_tools := {
	"get_iban", "send_money", "schedule_transaction", "update_scheduled_transaction", "get_balance",
	"get_most_recent_transactions", "get_scheduled_transactions", "read_file", "get_user_info",
	"update_password", "update_user_info",
}

egress := {
	"send_money": {"recipient": "account"},
	"schedule_transaction": {"recipient": "account"},
	"update_scheduled_transaction": {"recipient": "account"},
}

# Established payees: the user's own account plus every account the user has paid or has a standing
# order to. Incoming transfers do not make a sender a payee (anyone can send money with any subject).
internal := {"account": {
	"de89370400440532013000",
	"ch9300762011623852957", "gb29nwbk60161331926819", "se3550000000054910000003", "us122000000121212121212",
}}

high_risk_tools := {
	"send_money", "schedule_transaction", "update_scheduled_transaction", "update_password", "update_user_info",
}

user_supplied := {"update_password": ["password"]}
