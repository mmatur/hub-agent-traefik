package edge

import "time"

// Ingress represents an edge ingress configuration on a cluster.
type Ingress struct {
	ID string `json:"id"`

	WorkspaceID string `json:"workspaceId"`
	ClusterID   string `json:"clusterId"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`

	Domain  string   `json:"domain"`
	Service Service  `json:"service"`
	ACP     *ACPInfo `json:"acp,omitempty"`

	Version   string    `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Service represents an endpoint for an Ingress.
type Service struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// ACPInfo represents an ACP for an Ingress.
type ACPInfo struct {
	Name string `json:"name"`
}
