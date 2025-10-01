package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	pb "github.com/taskman/v2/services/user-service/pkg/api/api"
	"github.com/taskman/v2/services/user-service/internal/storage"
	"github.com/taskman/v2/shared/pkg/cache"
	"github.com/taskman/v2/shared/pkg/errors"
	"github.com/taskman/v2/shared/pkg/logger"
	"github.com/taskman/v2/shared/pkg/queue"
	"github.com/taskman/v2/shared/pkg/validation"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Service implements the UserService
type Service struct {
	pb.UnimplementedUserServiceServer
	storage *storage.Storage
	cache   *cache.Cache
	queue   *queue.Queue
	log     *logger.Logger
}

// Config holds service configuration
type Config struct {
	Storage *storage.Storage
	Cache   *cache.Cache
	Queue   *queue.Queue
	Logger  *logger.Logger
}

// New creates a new Service
func New(cfg *Config) *Service {
	return &Service{
		storage: cfg.Storage,
		cache:   cfg.Cache,
		queue:   cfg.Queue,
		log:     cfg.Logger,
	}
}

// Company operations

func (s *Service) CreateCompany(ctx context.Context, req *pb.CreateCompanyRequest) (*pb.CreateCompanyResponse, error) {
	// Validate input
	v := validation.New()
	v.Required("name", req.Name)
	v.Required("slug", req.Slug)

	if v.HasErrors() {
		err := v.FirstError()
		return nil, errors.InvalidArgument(err.Field, err.Message).ToGRPCError()
	}

	// Create company
	company := &storage.Company{
		ID:               storage.GenerateCompanyID(),
		Name:             req.Name,
		Slug:             req.Slug,
		SubscriptionTier: req.SubscriptionTier,
		MaxUsers:         int(req.MaxUsers),
		IsActive:         true,
		Settings:         req.Settings,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if company.SubscriptionTier == "" {
		company.SubscriptionTier = "free"
	}

	if company.MaxUsers == 0 {
		company.MaxUsers = 10
	}

	if err := s.storage.CreateCompany(ctx, company); err != nil {
		s.log.Error("failed to create company", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Publish event
	s.publishEvent(ctx, "user.company.created", map[string]interface{}{
		"company_id": company.ID,
		"name":       company.Name,
		"slug":       company.Slug,
	})

	return &pb.CreateCompanyResponse{
		Company: companyToProto(company),
	}, nil
}

func (s *Service) GetCompany(ctx context.Context, req *pb.GetCompanyRequest) (*pb.GetCompanyResponse, error) {
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	company, err := s.storage.GetCompany(ctx, req.CompanyId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	return &pb.GetCompanyResponse{
		Company: companyToProto(company),
	}, nil
}

func (s *Service) UpdateCompany(ctx context.Context, req *pb.UpdateCompanyRequest) (*pb.UpdateCompanyResponse, error) {
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	// Get existing company
	company, err := s.storage.GetCompany(ctx, req.CompanyId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Update fields
	if req.Name != "" {
		company.Name = req.Name
	}
	if req.SubscriptionTier != "" {
		company.SubscriptionTier = req.SubscriptionTier
	}
	if req.MaxUsers > 0 {
		company.MaxUsers = int(req.MaxUsers)
	}
	company.IsActive = req.IsActive
	if req.Settings != nil {
		company.Settings = req.Settings
	}

	if err := s.storage.UpdateCompany(ctx, company); err != nil {
		s.log.Error("failed to update company", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Publish event
	s.publishEvent(ctx, "user.company.updated", map[string]interface{}{
		"company_id": company.ID,
	})

	return &pb.UpdateCompanyResponse{
		Company: companyToProto(company),
	}, nil
}

func (s *Service) DeleteCompany(ctx context.Context, req *pb.DeleteCompanyRequest) (*pb.DeleteCompanyResponse, error) {
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	if err := s.storage.DeleteCompany(ctx, req.CompanyId); err != nil {
		s.log.Error("failed to delete company", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Publish event
	s.publishEvent(ctx, "user.company.deleted", map[string]interface{}{
		"company_id": req.CompanyId,
	})

	return &pb.DeleteCompanyResponse{Success: true}, nil
}

func (s *Service) ListCompanies(ctx context.Context, req *pb.ListCompaniesRequest) (*pb.ListCompaniesResponse, error) {
	page := int(req.Page)
	pageSize := int(req.PageSize)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	companies, totalCount, err := s.storage.ListCompanies(ctx, pageSize, offset)
	if err != nil {
		s.log.Error("failed to list companies", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	pbCompanies := make([]*pb.Company, 0, len(companies))
	for _, company := range companies {
		pbCompanies = append(pbCompanies, companyToProto(company))
	}

	return &pb.ListCompaniesResponse{
		Companies:  pbCompanies,
		TotalCount: int32(totalCount),
	}, nil
}

// User operations

func (s *Service) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	// Validate input
	v := validation.New()
	v.Required("company_id", req.CompanyId)
	v.Required("email", req.Email)
	v.Email("email", req.Email)
	v.Required("username", req.Username)
	v.Required("password", req.Password)

	if v.HasErrors() {
		err := v.FirstError()
		return nil, errors.InvalidArgument(err.Field, err.Message).ToGRPCError()
	}

	// Hash password
	passwordHash, err := storage.HashPassword(req.Password)
	if err != nil {
		s.log.Error("failed to hash password", "error", err)
		return nil, errors.Internal("failed to hash password").ToGRPCError()
	}

	// Create user
	user := &storage.User{
		ID:            storage.GenerateUserID(),
		CompanyID:     req.CompanyId,
		Email:         req.Email,
		Username:      req.Username,
		PasswordHash:  passwordHash,
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		Department:    sql.NullString{String: req.Department, Valid: req.Department != ""},
		Location:      sql.NullString{String: req.Location, Valid: req.Location != ""},
		AvatarURL:     sql.NullString{String: req.AvatarUrl, Valid: req.AvatarUrl != ""},
		IsActive:      true,
		EmailVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	if err := s.storage.CreateUser(ctx, user); err != nil {
		s.log.Error("failed to create user", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Publish event
	s.publishEvent(ctx, "user.created", map[string]interface{}{
		"user_id":    user.ID,
		"company_id": user.CompanyID,
		"email":      user.Email,
		"username":   user.Username,
	})

	return &pb.CreateUserResponse{
		User: userToProto(user, false), // Don't include password hash
	}, nil
}

func (s *Service) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	user, err := s.storage.GetUser(ctx, req.UserId, req.CompanyId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	return &pb.GetUserResponse{
		User: userToProto(user, false),
	}, nil
}

func (s *Service) GetUserByEmail(ctx context.Context, req *pb.GetUserByEmailRequest) (*pb.GetUserByEmailResponse, error) {
	if req.Email == "" {
		return nil, errors.InvalidArgument("email", "is required").ToGRPCError()
	}

	// company_id is optional during login - if empty, search across all companies
	// This is safe because this is a public method only used by auth service
	user, err := s.storage.GetUserByEmail(ctx, req.Email, req.CompanyId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	return &pb.GetUserByEmailResponse{
		User: userToProto(user, true), // Include password hash for authentication
	}, nil
}

func (s *Service) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	// Get existing user
	user, err := s.storage.GetUser(ctx, req.UserId, req.CompanyId)
	if err != nil {
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Update fields
	if req.Email != "" {
		user.Email = req.Email
	}
	if req.Username != "" {
		user.Username = req.Username
	}
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.Department != "" {
		user.Department = sql.NullString{String: req.Department, Valid: true}
	}
	if req.Location != "" {
		user.Location = sql.NullString{String: req.Location, Valid: true}
	}
	if req.AvatarUrl != "" {
		user.AvatarURL = sql.NullString{String: req.AvatarUrl, Valid: true}
	}
	user.IsActive = req.IsActive
	user.EmailVerified = req.EmailVerified

	if err := s.storage.UpdateUser(ctx, user); err != nil {
		s.log.Error("failed to update user", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Publish event
	s.publishEvent(ctx, "user.updated", map[string]interface{}{
		"user_id":    user.ID,
		"company_id": user.CompanyID,
	})

	return &pb.UpdateUserResponse{
		User: userToProto(user, false),
	}, nil
}

func (s *Service) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	if err := s.storage.DeleteUser(ctx, req.UserId, req.CompanyId); err != nil {
		s.log.Error("failed to delete user", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Publish event
	s.publishEvent(ctx, "user.deleted", map[string]interface{}{
		"user_id":    req.UserId,
		"company_id": req.CompanyId,
	})

	return &pb.DeleteUserResponse{Success: true}, nil
}

func (s *Service) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}

	page := int(req.Page)
	pageSize := int(req.PageSize)

	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	users, totalCount, err := s.storage.ListUsers(ctx, req.CompanyId, pageSize, offset, req.ActiveOnly)
	if err != nil {
		s.log.Error("failed to list users", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	pbUsers := make([]*pb.User, 0, len(users))
	for _, user := range users {
		pbUsers = append(pbUsers, userToProto(user, false))
	}

	return &pb.ListUsersResponse{
		Users:      pbUsers,
		TotalCount: int32(totalCount),
	}, nil
}

func (s *Service) SearchUsers(ctx context.Context, req *pb.SearchUsersRequest) (*pb.SearchUsersResponse, error) {
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}
	if req.Query == "" {
		return nil, errors.InvalidArgument("query", "is required").ToGRPCError()
	}

	limit := int(req.Limit)
	if limit < 1 || limit > 50 {
		limit = 10
	}

	users, err := s.storage.SearchUsers(ctx, req.CompanyId, req.Query, limit)
	if err != nil {
		s.log.Error("failed to search users", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	pbUsers := make([]*pb.User, 0, len(users))
	for _, user := range users {
		pbUsers = append(pbUsers, userToProto(user, false))
	}

	return &pb.SearchUsersResponse{
		Users: pbUsers,
	}, nil
}

func (s *Service) UpdatePassword(ctx context.Context, req *pb.UpdatePasswordRequest) (*pb.UpdatePasswordResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}
	if req.NewPassword == "" {
		return nil, errors.InvalidArgument("new_password", "is required").ToGRPCError()
	}

	// Get user to verify old password if provided
	if req.OldPassword != "" {
		user, err := s.storage.GetUser(ctx, req.UserId, req.CompanyId)
		if err != nil {
			return nil, err.(*errors.AppError).ToGRPCError()
		}

		if !storage.VerifyPassword(req.OldPassword, user.PasswordHash) {
			return nil, errors.Unauthenticated("old password is incorrect").ToGRPCError()
		}
	}

	// Hash new password
	newPasswordHash, err := storage.HashPassword(req.NewPassword)
	if err != nil {
		s.log.Error("failed to hash password", "error", err)
		return nil, errors.Internal("failed to hash password").ToGRPCError()
	}

	if err := s.storage.UpdatePassword(ctx, req.UserId, req.CompanyId, newPasswordHash); err != nil {
		s.log.Error("failed to update password", "error", err)
		return nil, err.(*errors.AppError).ToGRPCError()
	}

	// Publish event
	s.publishEvent(ctx, "user.password.updated", map[string]interface{}{
		"user_id":    req.UserId,
		"company_id": req.CompanyId,
	})

	return &pb.UpdatePasswordResponse{Success: true}, nil
}

func (s *Service) VerifyPassword(ctx context.Context, req *pb.VerifyPasswordRequest) (*pb.VerifyPasswordResponse, error) {
	if req.UserId == "" {
		return nil, errors.InvalidArgument("user_id", "is required").ToGRPCError()
	}
	if req.CompanyId == "" {
		return nil, errors.InvalidArgument("company_id", "is required").ToGRPCError()
	}
	if req.Password == "" {
		return nil, errors.InvalidArgument("password", "is required").ToGRPCError()
	}

	user, err := s.storage.GetUser(ctx, req.UserId, req.CompanyId)
	if err != nil {
		return &pb.VerifyPasswordResponse{Valid: false}, nil
	}

	valid := storage.VerifyPassword(req.Password, user.PasswordHash)

	return &pb.VerifyPasswordResponse{Valid: valid}, nil
}

func (s *Service) HealthCheck(ctx context.Context, req *pb.HealthCheckRequest) (*pb.HealthCheckResponse, error) {
	return &pb.HealthCheckResponse{
		Status:    "healthy",
		Timestamp: timestamppb.Now(),
	}, nil
}

// Helper functions

func (s *Service) publishEvent(ctx context.Context, eventType string, payload map[string]interface{}) {
	if s.queue == nil {
		return
	}

	event := &queue.Event{
		ID:        uuid.New().String(),
		Type:      eventType,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	if err := s.queue.Publish(ctx, eventType, event); err != nil {
		s.log.Warn("failed to publish event", "event_type", eventType, "error", err)
	}
}

func companyToProto(company *storage.Company) *pb.Company {
	return &pb.Company{
		Id:               company.ID,
		Name:             company.Name,
		Slug:             company.Slug,
		SubscriptionTier: company.SubscriptionTier,
		MaxUsers:         int32(company.MaxUsers),
		IsActive:         company.IsActive,
		Settings:         company.Settings,
		CreatedAt:        timestamppb.New(company.CreatedAt),
		UpdatedAt:        timestamppb.New(company.UpdatedAt),
	}
}

func userToProto(user *storage.User, includePasswordHash bool) *pb.User {
	var lastLoginAt *timestamppb.Timestamp
	if user.LastLoginAt.Valid {
		lastLoginAt = timestamppb.New(user.LastLoginAt.Time)
	}

	pbUser := &pb.User{
		Id:            user.ID,
		CompanyId:     user.CompanyID,
		Email:         user.Email,
		Username:      user.Username,
		FirstName:     user.FirstName,
		LastName:      user.LastName,
		AvatarUrl:     user.AvatarURL.String,
		Department:    user.Department.String,
		Location:      user.Location.String,
		IsActive:      user.IsActive,
		EmailVerified: user.EmailVerified,
		LastLoginAt:   lastLoginAt,
		CreatedAt:     timestamppb.New(user.CreatedAt),
		UpdatedAt:     timestamppb.New(user.UpdatedAt),
	}

	if includePasswordHash {
		pbUser.PasswordHash = user.PasswordHash
	}

	return pbUser
}
