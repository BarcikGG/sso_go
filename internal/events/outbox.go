// Package events publishes committed outbox entries to Kafka.
package events

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/segmentio/kafka-go"
)

// PublishOutbox keeps rows until Kafka acknowledges them. Duplicate sends are safe for
// consumers because every event has a stable ID.
func PublishOutbox(ctx context.Context, pool *pgxpool.Pool, broker, topic string) {
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
		tx, err := pool.Begin(ctx)
		if err != nil {
			log.Printf("outbox begin: %v", err)
			continue
		}
		var id, project, kind string
		var payload []byte
		err = tx.QueryRow(ctx, "SELECT id,project_id,event_type,payload FROM outbox WHERE published_at IS NULL ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED").Scan(&id, &project, &kind, &payload)
		if err != nil {
			_ = tx.Rollback(ctx)
			continue
		}
		var value any
		_ = json.Unmarshal(payload, &value)
		body, _ := json.Marshal(map[string]any{"id": id, "project_id": project, "type": kind, "payload": value})
		sendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = writer.WriteMessages(sendCtx, kafka.Message{Key: []byte(project), Value: body, Time: time.Now()})
		cancel()
		if err != nil {
			_, _ = tx.Exec(ctx, "UPDATE outbox SET attempts=attempts+1,last_error=$2 WHERE id=$1", id, err.Error())
			_ = tx.Commit(ctx)
			log.Printf("outbox publish: %v", err)
			continue
		}
		_, err = tx.Exec(ctx, "UPDATE outbox SET published_at=now(),attempts=attempts+1,last_error=NULL WHERE id=$1", id)
		if err != nil {
			_ = tx.Rollback(ctx)
			continue
		}
		_ = tx.Commit(ctx)
	}
}
