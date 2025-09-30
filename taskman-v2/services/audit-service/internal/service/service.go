package service

import (
	"context"
	"time"

	pb "github.com/taskman/v2/services/audit-service/pkg/api/api"
	"github.com/taskman/v2/services/audit-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/logger"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Service implements the AuditService
type Service struct {
	pb.UnimplementedAuditServiceServer
	storage *storage.Storage
	log     *logger.Logger
}

// Config holds service configuration
type Config struct {
	Storage *storage.Storage
	Logger  *logger.Logger
}

// New creates a new Service
func New(cfg *Config) *Service {
	return &Service{
		storage: cfg.Storage,
		log:     cfg.Logger,
	}
}

// LogEvent logs an audit event
func (s *Service) LogEvent(ctx context.Context, req *pb.LogEventRequest) (*pb.LogEventResponse, error) {
	// Convert metadata from proto map to Go map
	metadata := make(map[string]interface{})
	for k, v := range req.Metadata {
		metadata[k] = v
	}

	// Create event
	event := &storage.AuditEvent{
		ID:         storage.GenerateEventID(),
		EventType:  req.EventType,
		ActorID:    req.ActorId,
		ActorEmail: req.ActorEmail,
		TargetType: req.TargetType,
		TargetID:   req.TargetId,
		CompanyID:  req.CompanyId,
		Action:     req.Action,
		Result:     req.Result,
		IPAddress:  req.IpAddress,
		UserAgent:  req.UserAgent,
		Metadata:   metadata,
		Timestamp:  time.Now(),
	}

	// Store event
	if err := s.storage.LogEvent(ctx, event); err != nil {
		s.log.Error("failed to log event", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	return &pb.LogEventResponse{
		EventId:   event.ID,
		Timestamp: timestamppb.New(event.Timestamp),
	}, nil
}

// QueryEvents queries audit events with filters
func (s *Service) QueryEvents(ctx context.Context, req *pb.QueryEventsRequest) (*pb.QueryEventsResponse, error) {
	// Build filter
	filter := &storage.QueryFilter{
		CompanyID:  req.CompanyId,
		EventType:  req.EventType,
		ActorID:    req.ActorId,
		TargetType: req.TargetType,
		TargetID:   req.TargetId,
		Action:     req.Action,
		Result:     req.Result,
		Limit:      int(req.Limit),
		Offset:     int(req.Offset),
	}

	if req.StartTime != nil {
		startTime := req.StartTime.AsTime()
		filter.StartTime = &startTime
	}

	if req.EndTime != nil {
		endTime := req.EndTime.AsTime()
		filter.EndTime = &endTime
	}

	// Query events
	events, totalCount, err := s.storage.QueryEvents(ctx, filter)
	if err != nil {
		s.log.Error("failed to query events", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Convert to protobuf
	pbEvents := make([]*pb.AuditEvent, 0, len(events))
	for _, event := range events {
		metadata := make(map[string]string)
		for k, v := range event.Metadata {
			if strVal, ok := v.(string); ok {
				metadata[k] = strVal
			}
		}

		pbEvents = append(pbEvents, &pb.AuditEvent{
			Id:         event.ID,
			EventType:  event.EventType,
			ActorId:    event.ActorID,
			ActorEmail: event.ActorEmail,
			TargetType: event.TargetType,
			TargetId:   event.TargetID,
			CompanyId:  event.CompanyID,
			Action:     event.Action,
			Result:     event.Result,
			IpAddress:  event.IPAddress,
			UserAgent:  event.UserAgent,
			Metadata:   metadata,
			Timestamp:  timestamppb.New(event.Timestamp),
		})
	}

	return &pb.QueryEventsResponse{
		Events:     pbEvents,
		TotalCount: int32(totalCount),
	}, nil
}

// GetUserActivity retrieves audit trail for a specific user
func (s *Service) GetUserActivity(ctx context.Context, req *pb.UserActivityRequest) (*pb.UserActivityResponse, error) {
	// Build filter for events
	filter := &storage.QueryFilter{
		CompanyID: req.CompanyId,
		ActorID:   req.UserId,
		Limit:     int(req.Limit),
		Offset:    int(req.Offset),
	}

	if req.StartTime != nil {
		startTime := req.StartTime.AsTime()
		filter.StartTime = &startTime
	}

	if req.EndTime != nil {
		endTime := req.EndTime.AsTime()
		filter.EndTime = &endTime
	}

	// Get events
	events, totalCount, err := s.storage.QueryEvents(ctx, filter)
	if err != nil {
		s.log.Error("failed to get user activity", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Get activity summary
	summary, err := s.storage.GetUserActivity(ctx, req.UserId, req.CompanyId, filter.StartTime, filter.EndTime)
	if err != nil {
		s.log.Error("failed to get activity summary", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Convert events to protobuf
	pbEvents := make([]*pb.AuditEvent, 0, len(events))
	for _, event := range events {
		metadata := make(map[string]string)
		for k, v := range event.Metadata {
			if strVal, ok := v.(string); ok {
				metadata[k] = strVal
			}
		}

		pbEvents = append(pbEvents, &pb.AuditEvent{
			Id:         event.ID,
			EventType:  event.EventType,
			ActorId:    event.ActorID,
			ActorEmail: event.ActorEmail,
			TargetType: event.TargetType,
			TargetId:   event.TargetID,
			CompanyId:  event.CompanyID,
			Action:     event.Action,
			Result:     event.Result,
			IpAddress:  event.IPAddress,
			UserAgent:  event.UserAgent,
			Metadata:   metadata,
			Timestamp:  timestamppb.New(event.Timestamp),
		})
	}

	// Convert summary to protobuf
	actionsCount := make(map[string]int32)
	for k, v := range summary.ActionsCount {
		actionsCount[k] = int32(v)
	}

	eventTypesCount := make(map[string]int32)
	for k, v := range summary.EventTypesCount {
		eventTypesCount[k] = int32(v)
	}

	pbSummary := &pb.ActivitySummary{
		TotalEvents:      int32(summary.TotalEvents),
		SuccessCount:     int32(summary.SuccessCount),
		FailureCount:     int32(summary.FailureCount),
		ActionsCount:     actionsCount,
		EventTypesCount:  eventTypesCount,
	}

	return &pb.UserActivityResponse{
		Events:     pbEvents,
		TotalCount: int32(totalCount),
		Summary:    pbSummary,
	}, nil
}

// GetComplianceReport generates a compliance report
func (s *Service) GetComplianceReport(ctx context.Context, req *pb.ComplianceReportRequest) (*pb.ComplianceReportResponse, error) {
	// TODO: Implement comprehensive compliance reporting
	// This is a simplified version
	return &pb.ComplianceReportResponse{
		ReportId: storage.GenerateEventID(),
		Report: &pb.ComplianceReport{
			ReportType: req.ReportType,
			StartTime:  req.StartTime,
			EndTime:    req.EndTime,
			TotalEvents: 0,
			Metrics:    []*pb.ComplianceMetric{},
			SampleEvents: []*pb.AuditEvent{},
		},
	}, nil
}

// HealthCheck checks service health
func (s *Service) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Status:    "healthy",
		Timestamp: timestamppb.Now(),
	}, nil
}