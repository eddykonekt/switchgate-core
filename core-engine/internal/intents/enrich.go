package intents

// Enrich adds metadata or normalization to an intent.
// For now, this is just a stub.
func Enrich(msisdn string, telco string) map[string]string {
	return map[string]string{
		"msisdn": msisdn,
		"telco":  telco,
	}
}
