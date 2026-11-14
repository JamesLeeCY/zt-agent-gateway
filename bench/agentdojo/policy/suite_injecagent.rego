# InjecAgent tools (github.com/uiuc-kang-lab/InjecAgent, MIT; ToolEmu tool specs) mapped onto the gateway
# rules (gateway.rego) for bench/injecagent/replay.py. Same fields as suite_banking.rego.
#
# InjecAgent has no user directory (no contacts, payees or own accounts), so nothing is internal: every
# destination is external, and only a destination the user wrote in the request counts as vouched for.
# The mapping follows what each tool does (its ToolEmu spec), not which attacks use it.

package agentdojo.suites.injecagent

import rego.v1

# the 17 user tools and every attacker tool
known_tools := {
	"AmazonGetProductDetails", "AmazonViewSavedAddresses", "AmazonViewSavedPaymentMethods",
	"AugustSmartLockGrantGuestAccess", "AugustSmartLockUnlockDoor", "AugustSmartLockViewAccessHistory",
	"BankManagerGetAccountInformation", "BankManagerPayBill", "BankManagerSearchPayee",
	"BankManagerTransferFunds", "BinanceDeposit", "BinanceGetOrderHistory", "BinancePlaceOrder",
	"BinanceWithdraw", "CiscoUmbrellaCreatePolicy", "CiscoUmbrellaGetLogDetails", "CiscoUmbrellaUpdatePolicy",
	"DeepfakeGeneratorGenerateAudioDeepfake", "DropboxGetItemMetadata", "DropboxListFilesAndFolders",
	"DropboxMoveItem", "EmergencyDispatchSystemCreateDispatchRequest", "EpicFHIRDownloadFiles",
	"EpicFHIRGetPatientDetails", "EpicFHIRManageAppointments", "EpicFHIRManageClinicalDocuments",
	"EpicFHIRManagePatientRecords", "EvernoteManagerManageNoteSharingLevel", "EvernoteManagerSearchNotes",
	"ExpediaSearchReservations", "FacebookManagerGetUserProfile", "FacebookManagerSearchFriends",
	"FacebookManagerUpdateUserProfile", "FedExShipManagerManageShipment", "FedExShipManagerSearchShipment",
	"GitHubDeleteRepository", "GitHubGetRepositoryDetails", "GitHubGetUserDetails", "GitHubSearchRepositories",
	"GmailReadEmail", "GmailSearchEmails", "GmailSendEmail", "GoogleCalendarGetEventsFromSharedCalendar",
	"GoogleCalendarReadEvents", "GoogleHomeScheduleDeviceAction", "GoogleMapGetCurrentLocation",
	"GoogleSearchGetSearchHistory", "IndoorRobotGoToRoom", "InvestmentManagerGetHoldingsInformation",
	"NortonIdentitySafeAutoFillPersonalInfo", "NortonIdentitySafeDisableTwoFactorAuthentication",
	"NortonIdentitySafeSearchPasswords", "NortonIdentitySafeSharePassword", "ShopifyGetProductDetails",
	"SlackLeaveChannel", "SpokeoDownloadPublicRecord", "SpokeoSearchPeople",
	"TDAmeritradeGetHoldingsInformation", "TeladocAccessUserInfo", "TeladocViewPrescriptions",
	"TeladocViewReviews", "TerminalExecute", "The23andMeDownloadData", "The23andMeGetGeneticData",
	"The23andMeGetHealthRecommendations", "The23andMeShareData", "The23andMeUpdateData", "TodoistSearchTasks",
	"TrafficControlGivePriorityToEmergencyVehicle", "TrafficControlManageTrafficLightState",
	"TwilioGetPhoneNumberInfo", "TwilioGetReceivedSmsMessages", "TwitterManagerGetUserProfile",
	"TwitterManagerReadTweet", "TwitterManagerSearchTweets", "VenmoListLinkedAccounts", "VenmoWithdrawMoney",
	"WebBrowserNavigateTo", "WebBrowserSearchHistory",
}

egress := {
	"GmailSendEmail": {"to": "email", "cc": "email", "bcc": "email"},
	"EvernoteManagerManageNoteSharingLevel": {"email": "email"},
	"NortonIdentitySafeSharePassword": {"contact_email": "email"},
	"BankManagerTransferFunds": {"to_account_number": "account"},
	"BankManagerPayBill": {"payee_id": "payee"},
	"VenmoWithdrawMoney": {"account_id": "account"},
	"BinanceWithdraw": {"to_account_id": "account", "destination_address": "crypto_address"},
	"The23andMeShareData": {"app_id": "app"},
	"AugustSmartLockGrantGuestAccess": {"guest_ids": "guest"},
	"NortonIdentitySafeAutoFillPersonalInfo": {"website": "url"},
}

internal := {}

# every tool that changes something outside the conversation
high_risk_tools := {
	"AugustSmartLockGrantGuestAccess", "AugustSmartLockUnlockDoor", "BankManagerPayBill",
	"BankManagerTransferFunds", "BinanceDeposit", "BinancePlaceOrder", "BinanceWithdraw",
	"CiscoUmbrellaCreatePolicy", "CiscoUmbrellaUpdatePolicy", "DeepfakeGeneratorGenerateAudioDeepfake",
	"DropboxMoveItem", "EmergencyDispatchSystemCreateDispatchRequest", "EpicFHIRManageAppointments",
	"EpicFHIRManageClinicalDocuments", "EpicFHIRManagePatientRecords", "EvernoteManagerManageNoteSharingLevel",
	"FacebookManagerUpdateUserProfile", "FedExShipManagerManageShipment", "GitHubDeleteRepository",
	"GmailSendEmail", "GoogleHomeScheduleDeviceAction", "IndoorRobotGoToRoom",
	"NortonIdentitySafeAutoFillPersonalInfo", "NortonIdentitySafeDisableTwoFactorAuthentication",
	"NortonIdentitySafeSharePassword", "SlackLeaveChannel", "TerminalExecute", "The23andMeShareData",
	"The23andMeUpdateData", "TrafficControlGivePriorityToEmergencyVehicle",
	"TrafficControlManageTrafficLightState", "VenmoWithdrawMoney",
}

# security settings: the new value must come from the user's request once tainted
user_supplied := {
	"CiscoUmbrellaCreatePolicy": ["domains"],
	"CiscoUmbrellaUpdatePolicy": ["domains"],
	"FacebookManagerUpdateUserProfile": ["updates"],
}
