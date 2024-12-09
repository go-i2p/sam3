package sam3

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/go-i2p/i2pkeys"
)

// SAMResolver handles name resolution for I2P addresses
type SAMResolver struct {
    sam *SAM
}

// ResolveResult represents the possible outcomes of name resolution
type ResolveResult struct {
    Address i2pkeys.I2PAddr
    Error   error
}

const (
    defaultTimeout = 30 * time.Second
    samReplyPrefix = "NAMING REPLY "
)

// NewSAMResolver creates a resolver from an existing SAM instance
func NewSAMResolver(parent *SAM) (*SAMResolver, error) {
    if parent == nil {
        return nil, fmt.Errorf("parent SAM instance required")
    }
    return &SAMResolver{sam: parent}, nil
}

// NewFullSAMResolver creates a new resolver with its own SAM connection
func NewFullSAMResolver(address string) (*SAMResolver, error) {
    sam, err := NewSAM(address)
    if err != nil {
        return nil, fmt.Errorf("creating SAM connection: %w", err)
    }
    return &SAMResolver{sam: sam}, nil
}

func (r *SAMResolver) Resolve(name string) (i2pkeys.I2PAddr, error) {
    return r.ResolveWithContext(context.Background(), name)
}

// Resolve looks up an I2P address by name with context support
func (r *SAMResolver) ResolveWithContext(ctx context.Context, name string) (i2pkeys.I2PAddr, error) {
    if name == "" {
        return "", fmt.Errorf("name cannot be empty")
    }

    // Create query
    query := fmt.Sprintf("NAMING LOOKUP NAME=%s\n", name)
    
    // Set up timeout if context doesn't have one
    if _, hasTimeout := ctx.Deadline(); !hasTimeout {
        var cancel context.CancelFunc
        ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
        defer cancel()
    }

    // Write query with context awareness
    if err := r.writeWithContext(ctx, query); err != nil {
        return "", fmt.Errorf("writing query: %w", err)
    }

    // Read and parse response
    return r.readResponse(ctx, name)
}

func (r *SAMResolver) writeWithContext(ctx context.Context, query string) error {
    done := make(chan error, 1)
    
    go func() {
        _, err := r.sam.conn.Write([]byte(query))
        done <- err
    }()

    select {
    case err := <-done:
        return err
    case <-ctx.Done():
        return ctx.Err()
    }
}

func (r *SAMResolver) readResponse(ctx context.Context, name string) (i2pkeys.I2PAddr, error) {
    reader := bufio.NewReader(r.sam.conn)
    
    // Read first line
    line, err := reader.ReadString('\n')
    if err != nil {
        return "", fmt.Errorf("reading response: %w", err)
    }

    if !strings.HasPrefix(line, samReplyPrefix) {
        return "", fmt.Errorf("invalid response format")
    }

    // Parse response
    fields := strings.Fields(strings.TrimPrefix(line, samReplyPrefix))
    for _, field := range fields {
        switch {
        case field == "RESULT=OK":
            continue
        case field == "RESULT=INVALID_KEY":
            return "", fmt.Errorf("invalid key")
        case field == "RESULT=KEY_NOT_FOUND":
            return "", fmt.Errorf("name not found: %s", name)
        case field == "NAME="+name:
            continue
        case strings.HasPrefix(field, "VALUE="):
            return i2pkeys.I2PAddr(strings.TrimPrefix(field, "VALUE=")), nil
        case strings.HasPrefix(field, "MESSAGE="):
            return "", fmt.Errorf("SAM error: %s", strings.TrimPrefix(field, "MESSAGE="))
        }
    }

    return "", fmt.Errorf("unable to resolve %s", name)
}