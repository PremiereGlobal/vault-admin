package identity

// Group represents an identity group
type Group struct {
	// ID is the unique identifier for this group
	ID string `json:"id,omitempty",yaml:"id,omitempty"`
	// Name is the unique name for this group
	Name string `json:"name,omitempty",yaml:"policies,omitempty"`
	// Policies are the vault policies to be granted to members of this group
	Policies []string `json:"policies,omitempty",yaml:"policies,omitempty"`
	// MemberGroupIDs are the identifiers of those groups to which this group is a
	// member of. These are not configurable directly but will be populated
	MemberGroupIDs []string `json:"member_group_ids,omitempty",yaml:"member_group_ids,omitempty"`
	// MemberEntityIDs are the identifiers of entities which are members of this
	// group
	MemberEntityIDs []string `json:"member_entity_ids,omitempty",yaml:"member_entity_ids,omitempty"`
	// Metadata represents the custom data tied with this group
	Metadata map[string]string `json:"metadata,omitempty",yaml:"metadata,omitempty"`
	// Type indicates if this group is an internal group or an external group.
	// Memberships of the internal groups can be managed over the API whereas
	// the memberships on the external group --for which a corresponding alias
	// will be set-- will be managed automatically.
	Type string `json:"type,omitempty",yaml:"type,omitempty"`
}

type GroupList map[string]Group
