package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/sony/gobreaker"
)

// Config holds RabbitMQ configuration
type Config struct {
	URI              string
	ExchangeName     string
	ExchangeType     string // topic, fanout, direct, headers
	PrefetchCount    int
	ReconnectDelay   time.Duration
	PublishTimeout   time.Duration
	EnableCircuitBreaker bool
}

// Queue wraps RabbitMQ connection and channel
type Queue struct {
	config  *Config
	conn    *amqp.Connection
	channel *amqp.Channel
	breaker *gobreaker.CircuitBreaker
	closed  bool
}

// Event represents a message to be published/consumed
type Event struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload"`
}

// New creates a new RabbitMQ queue client
func New(config *Config) (*Queue, error) {
	q := &Queue{
		config: config,
	}

	if config.EnableCircuitBreaker {
		q.breaker = gobreaker.NewCircuitBreaker(gobreaker.Settings{
			Name:        "RabbitMQ",
			MaxRequests: 3,
			Interval:    time.Minute,
			Timeout:     30 * time.Second,
		})
	}

	if err := q.connect(); err != nil {
		return nil, err
	}

	return q, nil
}

// connect establishes connection to RabbitMQ
func (q *Queue) connect() error {
	conn, err := amqp.Dial(q.config.URI)
	if err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	channel, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to open channel: %w", err)
	}

	// Set QoS
	if q.config.PrefetchCount > 0 {
		if err := channel.Qos(q.config.PrefetchCount, 0, false); err != nil {
			channel.Close()
			conn.Close()
			return fmt.Errorf("failed to set QoS: %w", err)
		}
	}

	// Declare exchange
	if q.config.ExchangeName != "" {
		if err := channel.ExchangeDeclare(
			q.config.ExchangeName,
			q.config.ExchangeType,
			true,  // durable
			false, // auto-deleted
			false, // internal
			false, // no-wait
			nil,   // arguments
		); err != nil {
			channel.Close()
			conn.Close()
			return fmt.Errorf("failed to declare exchange: %w", err)
		}
	}

	q.conn = conn
	q.channel = channel
	q.closed = false

	return nil
}

// Publish publishes an event to the exchange
func (q *Queue) Publish(ctx context.Context, routingKey string, event *Event) error {
	if q.closed {
		return fmt.Errorf("queue is closed")
	}

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	publishFn := func() error {
		publishCtx, cancel := context.WithTimeout(ctx, q.config.PublishTimeout)
		defer cancel()

		return q.channel.PublishWithContext(
			publishCtx,
			q.config.ExchangeName,
			routingKey,
			true,  // mandatory
			false, // immediate
			amqp.Publishing{
				ContentType:  "application/json",
				Body:         body,
				DeliveryMode: amqp.Persistent,
				Timestamp:    event.Timestamp,
				MessageId:    event.ID,
				Type:         event.Type,
			},
		)
	}

	if q.breaker != nil {
		_, err = q.breaker.Execute(func() (interface{}, error) {
			return nil, publishFn()
		})
		return err
	}

	return publishFn()
}

// Consume starts consuming messages from a queue
func (q *Queue) Consume(queueName string, handler func(*Event) error) error {
	if q.closed {
		return fmt.Errorf("queue is closed")
	}

	// Declare queue
	queue, err := q.channel.QueueDeclare(
		queueName,
		true,  // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare queue: %w", err)
	}

	// Start consuming
	msgs, err := q.channel.Consume(
		queue.Name,
		"",    // consumer tag
		false, // auto-ack
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,   // args
	)
	if err != nil {
		return fmt.Errorf("failed to start consuming: %w", err)
	}

	// Process messages
	go func() {
		for msg := range msgs {
			var event Event
			if err := json.Unmarshal(msg.Body, &event); err != nil {
				msg.Nack(false, false) // Send to DLQ
				continue
			}

			if err := handler(&event); err != nil {
				msg.Nack(false, false) // Send to DLQ
			} else {
				msg.Ack(false)
			}
		}
	}()

	return nil
}

// BindQueue binds a queue to an exchange with a routing key
func (q *Queue) BindQueue(queueName, routingKey string) error {
	if q.closed {
		return fmt.Errorf("queue is closed")
	}

	// Declare queue
	_, err := q.channel.QueueDeclare(
		queueName,
		true,  // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare queue: %w", err)
	}

	// Bind queue to exchange
	err = q.channel.QueueBind(
		queueName,
		routingKey,
		q.config.ExchangeName,
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to bind queue: %w", err)
	}

	return nil
}

// DeclareQueue declares a queue
func (q *Queue) DeclareQueue(queueName string) error {
	if q.closed {
		return fmt.Errorf("queue is closed")
	}

	_, err := q.channel.QueueDeclare(
		queueName,
		true,  // durable
		false, // auto-delete
		false, // exclusive
		false, // no-wait
		nil,   // arguments
	)
	if err != nil {
		return fmt.Errorf("failed to declare queue: %w", err)
	}

	return nil
}

// Health checks RabbitMQ health
func (q *Queue) Health(ctx context.Context) error {
	if q.closed {
		return fmt.Errorf("queue is closed")
	}

	if q.conn == nil || q.conn.IsClosed() {
		return fmt.Errorf("RabbitMQ connection is closed")
	}

	if q.channel == nil {
		return fmt.Errorf("RabbitMQ channel is nil")
	}

	return nil
}

// Close closes the RabbitMQ connection
func (q *Queue) Close() error {
	if q.closed {
		return nil
	}

	q.closed = true

	if q.channel != nil {
		if err := q.channel.Close(); err != nil {
			return fmt.Errorf("failed to close channel: %w", err)
		}
	}

	if q.conn != nil {
		if err := q.conn.Close(); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	return nil
}

// Reconnect attempts to reconnect to RabbitMQ
func (q *Queue) Reconnect() error {
	if !q.closed {
		q.Close()
	}
	return q.connect()
}