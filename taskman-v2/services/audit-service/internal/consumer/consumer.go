package consumer

import (
	"context"

	"github.com/taskman/v2/services/audit-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/logger"
	"github.com/taskman/v2/shared/pkg/queue"
)

// EventConsumer consumes events from RabbitMQ and logs them to audit
type EventConsumer struct {
	queue   *queue.Queue
	storage *storage.Storage
	log     *logger.Logger
}

// New creates a new EventConsumer
func New(q *queue.Queue, storage *storage.Storage, log *logger.Logger) *EventConsumer {
	return &EventConsumer{
		queue:   q,
		storage: storage,
		log:     log,
	}
}

// Start starts consuming events
func (c *EventConsumer) Start(ctx context.Context) error {
	// Define queue bindings for different event types
	// Each queue will consume specific routing patterns from the audit.events exchange
	bindings := map[string]string{
		"audit.auth.events": "authz.#",  // Authorization/authentication events
		"audit.user.events": "user.#",   // User management events
		"audit.task.events": "task.#",   // Task management events
		"audit.iam.events":  "iam.#",    // IAM events
	}

	// Set up bindings and start consuming
	for queueName, routingKey := range bindings {
		// Bind queue to exchange with routing key
		if err := c.queue.BindQueue(queueName, routingKey); err != nil {
			c.log.Error("failed to bind queue", "queue", queueName, "routing_key", routingKey, "error", err)
			return err
		}
		c.log.Info("bound queue to exchange", "queue", queueName, "routing_key", routingKey)

		// Start consuming from queue
		if err := c.queue.Consume(queueName, c.handleEvent); err != nil {
			c.log.Error("failed to start consuming", "queue", queueName, "error", err)
			return err
		}
		c.log.Info("started consuming events", "queue", queueName)
	}

	return nil
}

// handleEvent processes an event and logs it to audit
func (c *EventConsumer) handleEvent(event *queue.Event) error {
	c.log.Debug("received event", "type", event.Type, "id", event.ID)

	// Extract common fields from payload
	actorID, _ := event.Payload["user_id"].(string)
	actorEmail, _ := event.Payload["email"].(string)
	targetID, _ := event.Payload["target_id"].(string)
	targetType, _ := event.Payload["target_type"].(string)
	companyID, _ := event.Payload["company_id"].(string)
	ipAddress, _ := event.Payload["ip_address"].(string)
	action, _ := event.Payload["action"].(string)

	// Determine result (default to success if not specified)
	result := "success"
	if resultVal, ok := event.Payload["result"].(string); ok {
		result = resultVal
	}

	// Create audit event
	auditEvent := &storage.AuditEvent{
		ID:         storage.GenerateEventID(),
		EventType:  event.Type,
		ActorID:    actorID,
		ActorEmail: actorEmail,
		TargetType: targetType,
		TargetID:   targetID,
		CompanyID:  companyID,
		Action:     action,
		Result:     result,
		IPAddress:  ipAddress,
		Metadata:   event.Payload,
		Timestamp:  event.Timestamp,
	}

	// Log event to database
	if err := c.storage.LogEvent(context.Background(), auditEvent); err != nil {
		c.log.Error("failed to log audit event",
			"event_type", event.Type,
			"event_id", event.ID,
			"error", err,
		)
		return err
	}

	c.log.Debug("logged audit event", "event_id", auditEvent.ID, "type", event.Type)
	return nil
}