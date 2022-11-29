// Package service contains all the services used by XrayR
// To implement a service, one needs to implement the interface below.
package service

// Service is the interface of all the services running in the panel
type Service interface {
	Start() error
	Close() error
	Restart
}

// Restart the service
type Restart interface {
	Start() error
	Close() error
}
