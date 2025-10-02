package clients

import (
	auditPb "github.com/taskman/v2/services/audit-service/pkg/api/api"
	"github.com/taskman/v2/shared/pkg/grpcclient"
	"google.golang.org/grpc"
)

// AuditClient wraps the audit service gRPC client
type AuditClient struct {
	conn   *grpc.ClientConn
	Client auditPb.AuditServiceClient
}

// NewAuditClient creates a new audit service client
func NewAuditClient(addr string) (*AuditClient, error) {
	conn, err := grpcclient.Connect(grpcclient.DefaultConfig(addr))
	if err != nil {
		return nil, err
	}

	return &AuditClient{
		conn:   conn,
		Client: auditPb.NewAuditServiceClient(conn),
	}, nil
}

// Close closes the connection
func (c *AuditClient) Close() error {
	return c.conn.Close()
}
