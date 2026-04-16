package auth

import (
	"context"
	"time"
)

type RequestMetadata struct {
	RequestID string
	ClientIP  string
	UserAgent string
}

type AuditEvent struct {
	ID        string
	UserID    string
	EventType string
	Metadata  map[string]any
	CreatedAt time.Time
}

type AuditStore interface {
	RecordAuditEvent(ctx context.Context, event AuditEvent) error
}

type requestMetadataContextKey struct{}

func WithRequestMetadata(ctx context.Context, metadata RequestMetadata) context.Context {
	return context.WithValue(ctx, requestMetadataContextKey{}, metadata)
}

func RequestMetadataFromContext(ctx context.Context) RequestMetadata {
	metadata, ok := ctx.Value(requestMetadataContextKey{}).(RequestMetadata)
	if !ok {
		return RequestMetadata{}
	}

	return metadata
}
