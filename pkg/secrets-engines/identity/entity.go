package identity

// Entity represents an identity entity
type Entity struct {
	// ID is the unique identifier of the entity which always be a UUID. This
	// should never be allowed to be updated.
	ID string
	// Name is a unique identifier of the entity which is intended to be
	// human-friendly.
	Name string `json:"name,omitempty",yaml:"name,omitempty"`
	// Metadata represents the explicit metadata which is set by the
	// clients.  This is useful to tie any information pertaining to the
	// aliases. This is a non-unique field of entity, meaning multiple
	// entities can have the same metadata set. Entities will be indexed based
	// on this explicit metadata. This enables virtual groupings of entities
	// based on its metadata.
	Metadata map[string]string `json:"metadata,omitempty",yaml:"metadata,omitempty"`
	// Policies the entity is entitled to
	Policies []string `json:"policies,omitempty",yaml:"policies,omitempty"`
	// Disabled indicates whether tokens associated with the account should not
	// be able to be used
	Disabled bool `json:"disabled,omitempty",yaml:"disabled,omitempty"`
}

type EntityList map[string]Entity

func (entityList EntityList) GetEntityByID(id string) *Entity {
	for _, e := range entityList {
		if e.ID == id {
			return &e
		}
	}

	return nil
}
