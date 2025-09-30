package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/taskman/v2/shared/pkg/database"
	"github.com/taskman/v2/shared/pkg/errors"
)

// AuditEvent represents an audit event
type AuditEvent struct {
	ID         string
	EventType  string
	ActorID    string
	ActorEmail string
	TargetType string
	TargetID   string
	CompanyID  string
	Action     string
	Result     string
	IPAddress  string
	UserAgent  string
	Metadata   map[string]interface{}
	Timestamp  time.Time
}

// QueryFilter represents filters for querying audit events
type QueryFilter struct {
	CompanyID  string
	EventType  string
	ActorID    string
	TargetType string
	TargetID   string
	Action     string
	Result     string
	StartTime  *time.Time
	EndTime    *time.Time
	Limit      int
	Offset     int
}

// ActivitySummary represents activity statistics
type ActivitySummary struct {
	TotalEvents      int
	SuccessCount     int
	FailureCount     int
	ActionsCount     map[string]int
	EventTypesCount  map[string]int
}

// Storage provides database operations for audit service
type Storage struct {
	db *database.DB
}

// New creates a new Storage instance
func New(db *database.DB) *Storage {
	return &Storage{db: db}
}

// LogEvent inserts a new audit event
func (s *Storage) LogEvent(ctx context.Context, event *AuditEvent) error {
	query := `
		INSERT INTO audit_events (
			id, event_type, actor_id, actor_email, target_type, target_id,
			company_id, action, result, ip_address, user_agent, metadata, timestamp
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	// Convert metadata to JSONB
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to marshal metadata").Code, "failed to marshal metadata")
	}

	_, err = s.db.ExecContext(ctx, query,
		event.ID,
		event.EventType,
		nullString(event.ActorID),
		nullString(event.ActorEmail),
		nullString(event.TargetType),
		nullString(event.TargetID),
		event.CompanyID,
		event.Action,
		event.Result,
		nullString(event.IPAddress),
		nullString(event.UserAgent),
		metadataJSON,
		event.Timestamp,
	)

	if err != nil {
		return errors.Wrap(err, errors.Internal("failed to log event").Code, "failed to insert audit event")
	}

	return nil
}

// QueryEvents queries audit events with filters
func (s *Storage) QueryEvents(ctx context.Context, filter *QueryFilter) ([]*AuditEvent, int, error) {
	// Build query dynamically based on filters
	query := `
		SELECT
			id, event_type, actor_id, actor_email, target_type, target_id,
			company_id, action, result, ip_address, user_agent, metadata, timestamp
		FROM audit_events
		WHERE 1=1
	`
	countQuery := "SELECT COUNT(*) FROM audit_events WHERE 1=1"
	args := make([]interface{}, 0)
	argIndex := 1

	// Add filters
	if filter.CompanyID != "" {
		query += fmt.Sprintf(" AND company_id = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND company_id = $%d", argIndex)
		args = append(args, filter.CompanyID)
		argIndex++
	}

	if filter.EventType != "" {
		query += fmt.Sprintf(" AND event_type = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND event_type = $%d", argIndex)
		args = append(args, filter.EventType)
		argIndex++
	}

	if filter.ActorID != "" {
		query += fmt.Sprintf(" AND actor_id = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND actor_id = $%d", argIndex)
		args = append(args, filter.ActorID)
		argIndex++
	}

	if filter.TargetType != "" {
		query += fmt.Sprintf(" AND target_type = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND target_type = $%d", argIndex)
		args = append(args, filter.TargetType)
		argIndex++
	}

	if filter.TargetID != "" {
		query += fmt.Sprintf(" AND target_id = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND target_id = $%d", argIndex)
		args = append(args, filter.TargetID)
		argIndex++
	}

	if filter.Action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND action = $%d", argIndex)
		args = append(args, filter.Action)
		argIndex++
	}

	if filter.Result != "" {
		query += fmt.Sprintf(" AND result = $%d", argIndex)
		countQuery += fmt.Sprintf(" AND result = $%d", argIndex)
		args = append(args, filter.Result)
		argIndex++
	}

	if filter.StartTime != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		countQuery += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, *filter.StartTime)
		argIndex++
	}

	if filter.EndTime != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		countQuery += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, *filter.EndTime)
		argIndex++
	}

	// Get total count
	var totalCount int
	err := s.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.Internal("failed to count events").Code, "failed to execute count query")
	}

	// Add ordering, limit, and offset
	query += " ORDER BY timestamp DESC"
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
	}

	// Execute query
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.Internal("failed to query events").Code, "failed to execute query")
	}
	defer rows.Close()

	// Parse results
	events := make([]*AuditEvent, 0)
	for rows.Next() {
		var event AuditEvent
		var actorID, actorEmail, targetType, targetID, ipAddress, userAgent sql.NullString
		var metadataJSON []byte

		err := rows.Scan(
			&event.ID,
			&event.EventType,
			&actorID,
			&actorEmail,
			&targetType,
			&targetID,
			&event.CompanyID,
			&event.Action,
			&event.Result,
			&ipAddress,
			&userAgent,
			&metadataJSON,
			&event.Timestamp,
		)
		if err != nil {
			return nil, 0, errors.Wrap(err, errors.Internal("failed to scan event").Code, "failed to scan row")
		}

		// Handle nullable fields
		if actorID.Valid {
			event.ActorID = actorID.String
		}
		if actorEmail.Valid {
			event.ActorEmail = actorEmail.String
		}
		if targetType.Valid {
			event.TargetType = targetType.String
		}
		if targetID.Valid {
			event.TargetID = targetID.String
		}
		if ipAddress.Valid {
			event.IPAddress = ipAddress.String
		}
		if userAgent.Valid {
			event.UserAgent = userAgent.String
		}

		// Parse metadata JSON
		if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
			event.Metadata = make(map[string]interface{})
		}

		events = append(events, &event)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, errors.Wrap(err, errors.Internal("failed to iterate events").Code, "failed to iterate rows")
	}

	return events, totalCount, nil
}

// GetUserActivity retrieves activity summary for a user
func (s *Storage) GetUserActivity(ctx context.Context, userID, companyID string, startTime, endTime *time.Time) (*ActivitySummary, error) {
	query := `
		SELECT
			COUNT(*) AS total_events,
			COUNT(*) FILTER (WHERE result = 'success') AS success_count,
			COUNT(*) FILTER (WHERE result = 'failure') AS failure_count,
			json_object_agg(action, action_count) AS actions_count,
			json_object_agg(event_type, event_type_count) AS event_types_count
		FROM (
			SELECT
				result,
				action,
				event_type,
				COUNT(*) OVER (PARTITION BY action) AS action_count,
				COUNT(*) OVER (PARTITION BY event_type) AS event_type_count
			FROM audit_events
			WHERE actor_id = $1 AND company_id = $2
	`

	args := []interface{}{userID, companyID}
	argIndex := 3

	if startTime != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, *startTime)
		argIndex++
	}

	if endTime != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, *endTime)
	}

	query += ") AS subquery"

	var summary ActivitySummary
	var actionsJSON, eventTypesJSON []byte

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&summary.TotalEvents,
		&summary.SuccessCount,
		&summary.FailureCount,
		&actionsJSON,
		&eventTypesJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return &ActivitySummary{
				ActionsCount:    make(map[string]int),
				EventTypesCount: make(map[string]int),
			}, nil
		}
		return nil, errors.Wrap(err, errors.Internal("failed to get user activity").Code, "failed to query user activity")
	}

	// Parse JSON aggregations
	if err := json.Unmarshal(actionsJSON, &summary.ActionsCount); err != nil {
		summary.ActionsCount = make(map[string]int)
	}
	if err := json.Unmarshal(eventTypesJSON, &summary.EventTypesCount); err != nil {
		summary.EventTypesCount = make(map[string]int)
	}

	return &summary, nil
}

// Helper function to handle nullable strings
func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

// GenerateEventID generates a new event ID
func GenerateEventID() string {
	return uuid.New().String()
}