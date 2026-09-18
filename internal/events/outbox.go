// Package events publishes committed outbox entries to Kafka.
package events

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/endl/sso_go/internal/repository/postgres"
	"github.com/segmentio/kafka-go"
)

// PublishOutbox keeps rows until Kafka acknowledges them. Duplicate sends are safe for
// consumers because every event has a stable ID.
func PublishOutbox(ctx context.Context, repo *postgres.DB, broker, topic string) {
	if broker == "" {
		return
	}
	writer := &kafka.Writer{Addr: kafka.TCP(broker), Topic: topic, RequiredAcks: kafka.RequireAll, Balancer: &kafka.Hash{}, BatchTimeout: 100 * time.Millisecond}
	defer writer.Close()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		_, err := repo.PublishNext(ctx, func(entry postgres.OutboxEntry) error {
			var value any
			if err := json.Unmarshal(entry.Payload, &value); err != nil {
				return err
			}
			body, err := json.Marshal(map[string]any{"id": entry.ID, "project_id": entry.Project, "type": entry.Kind, "payload": value})
			if err != nil {
				return err
			}
			sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return writer.WriteMessages(sendCtx, kafka.Message{Key: []byte(entry.Project), Value: body, Time: time.Now()})
		})
		if err != nil {
			log.Printf("outbox publish: %v", err)
		}
	}
}
