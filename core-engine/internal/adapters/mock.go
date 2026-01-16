package adapters

// Adapter defines provider adapter interface.
type Adapter interface {
	Send(msisdn string, amount string) error
}

// MockAdapter is a stub adapter for testing.
type MockAdapter struct{}

func NewMockAdapter() *MockAdapter {
	return &MockAdapter{}
}

func (m *MockAdapter) Send(msisdn string, amount string) error {
	// Stub: pretend to send
	return nil
}
