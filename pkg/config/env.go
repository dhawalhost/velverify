package config

import "os"

// lookupEnvOS looks up an environment variable.
func lookupEnvOS(key string) (string, bool) {
	return os.LookupEnv(key)
}
