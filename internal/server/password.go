package server

// GenerateBootstrapPassword returns a random high-entropy password for the admin account.
func GenerateBootstrapPassword() (string, error) {
	return randomToken(18), nil
}
