package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	auditPb "github.com/taskman/v2/services/audit-service/pkg/api/api"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// HandleQueryAuditLogs queries audit logs with filters
func (h *Handler) HandleQueryAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET requests are allowed")
		return
	}

	token := extractTokenFromHeader(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization token")
		return
	}

	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token")
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Build filter
	req := &auditPb.QueryEventsRequest{
		CompanyId:  claims.CompanyID,
		EventType:  query.Get("event_type"),
		ActorId:    query.Get("actor_id"),
		TargetType: query.Get("target_type"),
		TargetId:   query.Get("target_id"),
		Action:     query.Get("action"),
		Result:     query.Get("result"),
		Limit:      parseInt32(query.Get("limit"), 50),
		Offset:     parseInt32(query.Get("offset"), 0),
	}

	// Parse time range
	if startTime := query.Get("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			req.StartTime = timestamppb.New(t)
		}
	}
	if endTime := query.Get("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			req.EndTime = timestamppb.New(t)
		}
	}

	// Query audit service
	ctx := contextWithAuth(r.Context(), token)
	resp, err := h.AuditClient.Client.QueryEvents(ctx, req)
	if err != nil {
		h.Logger.Error("failed to query audit logs", "error", err)
		statusCode, errorCode, errorMessage := extractGRPCError(err)
		respondWithError(w, statusCode, errorCode, errorMessage)
		return
	}

	// Convert response
	events := make([]map[string]interface{}, 0, len(resp.Events))
	for _, event := range resp.Events {
		events = append(events, map[string]interface{}{
			"id":          event.Id,
			"event_type":  event.EventType,
			"actor_id":    event.ActorId,
			"actor_email": event.ActorEmail,
			"target_type": event.TargetType,
			"target_id":   event.TargetId,
			"company_id":  event.CompanyId,
			"action":      event.Action,
			"result":      event.Result,
			"ip_address":  event.IpAddress,
			"user_agent":  event.UserAgent,
			"metadata":    event.Metadata,
			"timestamp":   event.Timestamp.AsTime().Format(time.RFC3339),
		})
	}

	response := map[string]interface{}{
		"success":     true,
		"events":      events,
		"total_count": resp.TotalCount,
		"limit":       req.Limit,
		"offset":      req.Offset,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// HandleGetUserActivity gets audit trail for a specific user
func (h *Handler) HandleGetUserActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET requests are allowed")
		return
	}

	token := extractTokenFromHeader(r)
	if token == "" {
		respondWithError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing authorization token")
		return
	}

	claims, err := h.JWTManager.VerifyAccessToken(token)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "INVALID_TOKEN", "Invalid or expired token")
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	userID := query.Get("user_id")
	if userID == "" {
		userID = claims.UserID // Default to current user
	}

	req := &auditPb.UserActivityRequest{
		UserId:    userID,
		CompanyId: claims.CompanyID,
		Limit:     parseInt32(query.Get("limit"), 100),
		Offset:    parseInt32(query.Get("offset"), 0),
	}

	// Parse time range
	if startTime := query.Get("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			req.StartTime = timestamppb.New(t)
		}
	}
	if endTime := query.Get("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			req.EndTime = timestamppb.New(t)
		}
	}

	// Query audit service
	ctx := contextWithAuth(r.Context(), token)
	resp, err := h.AuditClient.Client.GetUserActivity(ctx, req)
	if err != nil {
		h.Logger.Error("failed to get user activity", "error", err)
		statusCode, errorCode, errorMessage := extractGRPCError(err)
		respondWithError(w, statusCode, errorCode, errorMessage)
		return
	}

	// Convert response
	events := make([]map[string]interface{}, 0, len(resp.Events))
	for _, event := range resp.Events {
		events = append(events, map[string]interface{}{
			"id":          event.Id,
			"event_type":  event.EventType,
			"actor_id":    event.ActorId,
			"actor_email": event.ActorEmail,
			"target_type": event.TargetType,
			"target_id":   event.TargetId,
			"company_id":  event.CompanyId,
			"action":      event.Action,
			"result":      event.Result,
			"ip_address":  event.IpAddress,
			"user_agent":  event.UserAgent,
			"metadata":    event.Metadata,
			"timestamp":   event.Timestamp.AsTime().Format(time.RFC3339),
		})
	}

	response := map[string]interface{}{
		"success":     true,
		"events":      events,
		"total_count": resp.TotalCount,
		"summary": map[string]interface{}{
			"total_events":      resp.Summary.TotalEvents,
			"success_count":     resp.Summary.SuccessCount,
			"failure_count":     resp.Summary.FailureCount,
			"actions_count":     resp.Summary.ActionsCount,
			"event_types_count": resp.Summary.EventTypesCount,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
