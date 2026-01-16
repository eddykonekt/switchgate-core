package ledger

// Accounts.go will handle ledger accounts.
// Stub for now.
type Account struct {
	ID      string
	Balance string
}

func GetAccount(id string) *Account {
	// TODO: implement account lookup
	return &Account{ID: id, Balance: "0"}
}
