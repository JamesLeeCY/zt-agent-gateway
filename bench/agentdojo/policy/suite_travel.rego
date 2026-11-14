# AgentDojo travel tools mapped onto the gateway rules (gateway.rego); see suite_banking.rego for the fields.
# Directory from the suite's default environment (agentdojo 0.1.35, v1.2.2), lower case.
package agentdojo.suites.travel

import rego.v1

known_tools := {
	"get_user_information", "get_all_hotels_in_city", "get_hotels_prices", "get_rating_reviews_for_hotels",
	"get_hotels_address", "get_all_restaurants_in_city", "get_cuisine_type_for_restaurants",
	"get_restaurants_address", "get_rating_reviews_for_restaurants", "get_dietary_restrictions_for_all_restaurants",
	"get_contact_information_for_restaurants", "get_price_for_restaurants", "check_restaurant_opening_hours",
	"get_all_car_rental_companies_in_city", "get_car_types_available", "get_rating_reviews_for_car_rental",
	"get_car_fuel_options", "get_car_rental_address", "get_car_price_per_day", "create_calendar_event",
	"search_calendar_events", "get_day_calendar_events", "cancel_calendar_event", "reserve_hotel",
	"reserve_car_rental", "reserve_restaurant", "get_flight_information", "send_email",
}

egress := {
	"send_email": {"recipients": "email", "cc": "email", "bcc": "email"},
	"create_calendar_event": {"participants": "email"},
}

# The user's own mailbox and the colleagues in the user's calendar (same company as the workspace suite).
internal := {"email": {
	"emma.johnson@bluesparrowtech.com", "michael.smith@bluesparrowtech.com", "sara.lee@bluesparrowtech.com",
}}

# Bookings commit the user's money; mail and calendar invites are outward-facing.
high_risk_tools := {
	"send_email", "create_calendar_event", "cancel_calendar_event", "reserve_hotel", "reserve_car_rental",
	"reserve_restaurant",
}

user_supplied := {}

# bookings pay a hotel or restaurant, not a destination named in the call
value_tools := set()

protection_lowering_tools := set()
