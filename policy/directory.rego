# Internal recipient allowlist ("directory"). Being on the internal domain is NOT enough to be trusted:
# shared, relay and auto-forwarding mailboxes on bank.example.com can still carry data outside the bank,
# so only mailboxes listed here count as internal. In production this would be fed from the IdP/HR
# directory as OPA data (bundle), with forwarding mailboxes excluded.
package agent.directory

import rego.v1

internal_mailboxes := {
	"wendy.chen@bank.example.com",
	"compliance@bank.example.com",
	"rm_042@bank.example.com",
	"rm_007@bank.example.com",
}
