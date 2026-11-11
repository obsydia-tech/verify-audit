package audit

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Refused is the error a service returns when it refuses an operation
// because its audit log cannot be written.
func Refused(service, node string, err error) error {
	return status.Errorf(codes.FailedPrecondition, "%s(%s) on %s: %v", UnavailableMarker, service, node, err)
}
