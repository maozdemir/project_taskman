package clients

import (
	"context"

	userPb "github.com/taskman/v2/services/user-service/pkg/api/api"
	"github.com/taskman/v2/shared/pkg/grpcclient"
	"google.golang.org/grpc"
)

// UserClient wraps the user service gRPC client
type UserClient struct {
	conn   *grpc.ClientConn
	Client userPb.UserServiceClient
}

// NewUserClient creates a new user service client
func NewUserClient(addr string) (*UserClient, error) {
	conn, err := grpcclient.Connect(grpcclient.DefaultConfig(addr))
	if err != nil {
		return nil, err
	}

	return &UserClient{
		conn:   conn,
		Client: userPb.NewUserServiceClient(conn),
	}, nil
}

// GetUserByEmail retrieves a user by email (company_id is optional for cross-company search)
func (c *UserClient) GetUserByEmail(ctx context.Context, email string) (*userPb.User, error) {
	resp, err := c.Client.GetUserByEmail(ctx, &userPb.GetUserByEmailRequest{
		Email: email,
		// CompanyId is omitted - allows searching across all companies during login
	})
	if err != nil {
		return nil, err
	}
	return resp.User, nil
}

// VerifyPassword verifies a user's password
func (c *UserClient) VerifyPassword(ctx context.Context, userID, companyID, password string) (bool, error) {
	resp, err := c.Client.VerifyPassword(ctx, &userPb.VerifyPasswordRequest{
		UserId:    userID,
		CompanyId: companyID,
		Password:  password,
	})
	if err != nil {
		return false, err
	}
	return resp.Valid, nil
}

// CreateUser creates a new user
func (c *UserClient) CreateUser(ctx context.Context, req *userPb.CreateUserRequest) (*userPb.User, error) {
	resp, err := c.Client.CreateUser(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.User, nil
}

// CreateCompany creates a new company
func (c *UserClient) CreateCompany(ctx context.Context, req *userPb.CreateCompanyRequest) (*userPb.Company, error) {
	resp, err := c.Client.CreateCompany(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Company, nil
}

// Close closes the connection
func (c *UserClient) Close() error {
	return c.conn.Close()
}
