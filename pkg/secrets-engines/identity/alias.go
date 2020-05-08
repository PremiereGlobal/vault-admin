package identity

// Alias represents an identity alias
type Alias struct {
	// ID is the unique identifier that represents this alias
	ID string `json:"id,omitempty",yaml:"id,omitempty"`
	// CanonicalID is the identifier to which this alias belongs to  (group or entity ID)
	CanonicalID string `json:"canonical_id,omitempty",yaml:"canonical_id,omitempty"`
  // CanonicalName is the identifier to which this alias belongs to (group or entity name)
	CanonicalName string `json:"canonical_name,omitempty",yaml:"canonical_name,omitempty"`
	// MountAccessor is the backend mount's accessor to which this alias
	// belongs to.
	MountAccessor string `json:"mount_accessor,omitempty",yaml:"mount_accessor,omitempty"`
	// MountPath is the backend mount's path to which the Maccessor belongs to.
	MountPath string `json:"mount_path,omitempty",yaml:"mount_path,omitempty"`
	// MountType is the backend mount's type
	MountType string `json:"mount_type,omitempty",yaml:"mount_type,omitempty"`
	// Name is the identifier of this alias in its authentication source.
	// This does not uniquely identify an alias in Vault. This in conjunction
	// with MountAccessor form to be the factors that represent an alias in a
	// unique way. Aliases will be indexed based on this combined uniqueness
	// factor.
	Name string `json:"name,omitempty",yaml:"name,omitempty"`
}

type AliasList map[string]Alias

func (aliasList AliasList) Exists(alias Alias) (bool, string) {
  for id, a := range aliasList {
    if a.MountAccessor == alias.MountAccessor && a.Name == alias.Name {
      return true, id
    }
  }

  return false, ""
}

// CleanFields empties any fields that should not be sent to the Vault API
func (alias *Alias) CleanFields() (Alias) {
  var a Alias
  a.ID = alias.ID
  a.Name = alias.Name
  a.MountAccessor = alias.MountAccessor
  a.CanonicalID = alias.CanonicalID

  return a
}
