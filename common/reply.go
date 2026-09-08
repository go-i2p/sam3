// common/reply.go
package common

import (
	"fmt"
	"strings"
)

// Reply represents a parsed SAM bridge response
type Reply struct {
	Topic     string            // e.g., "HELLO", "SESSION", "STREAM", etc.
	Type      string            // Usually "REPLY"
	Result    string            // "OK" or error message
	KeyValues map[string]string // Additional key-value pairs in the response
}

// ParseReply parses a raw SAM bridge response into a structured Reply
func ParseReply(response string) (*Reply, error) {
	parts := strings.Fields(response)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid reply format: %s", response)
	}

	reply := &Reply{
		Topic:     parts[0],
		Type:      parts[1],
		KeyValues: make(map[string]string),
	}

	// Parse remaining key=value pairs
	for _, part := range parts[2:] {
		if kv := strings.SplitN(part, "=", 2); len(kv) == 2 {
			key := strings.ToUpper(kv[0])
			if key == "RESULT" {
				reply.Result = kv[1]
			} else {
				reply.KeyValues[key] = kv[1]
			}
		}
	}

	if reply.Result == "" {
		return nil, fmt.Errorf("missing RESULT in reply: %s", response)
	}

	return reply, nil
}

// IsOk returns true if the reply indicates success
func (r *Reply) IsOk() bool {
	return r.Result == "OK"
}

// Error returns an error if the reply indicates failure
func (r *Reply) Error() error {
	if r.IsOk() {
		return nil
	}
	return fmt.Errorf("%s failed: %s", r.Topic, r.Result)
}

// Value safely retrieves a value from KeyValues
func (r *Reply) Value(key string) (string, bool) {
	v, ok := r.KeyValues[strings.ToUpper(key)]
	return v, ok
}

// MustValue gets a value or panics if not found
func (r *Reply) MustValue(key string) string {
	if v, ok := r.Value(key); ok {
		return v
	}
	panic(fmt.Sprintf("required key not found: %s", key))
}

// Specific reply type checkers
func (r *Reply) IsHello() bool {
	return r.Topic == HelloMsg && r.Type == "REPLY"
}

func (r *Reply) IsSession() bool {
	return r.Topic == SessionMsg && r.Type == "REPLY"
}

func (r *Reply) IsNaming() bool {
	return r.Topic == NamingMsg && r.Type == "REPLY"
}
