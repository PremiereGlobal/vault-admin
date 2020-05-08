package auth

// Group represents an auth mount
type Mount struct {
  // Type of the mount (token, ldap, etc.)
  Type string `json:"type,omitempty",yaml:"type,omitempty"`
  
  // Description of the mount
  Description string `json:"description,omitempty",yaml:"description,omitempty"`

  // Accessor (ID) of the mount (i.e. auth_token_918a038a)
  Accessor string `json:"accessor,omitempty",yaml:"accessor,omitempty"`
}
