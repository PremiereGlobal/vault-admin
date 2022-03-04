package main

import (
	"time"

	"github.com/hashicorp/go-sockaddr"
)

type TokenAttributes struct {

	// Name of the role.
	// https://www.vaultproject.io/api-docs/auth/kubernetes#name
	Name string `json:"name" yaml:"name"`

	// The incremental lifetime for generated tokens. This current value of this will be referenced at renewal time.
	TokenTTL time.Duration `json:"token_ttl" yaml:"token_ttl"`

	// The maximum lifetime for generated tokens. This current value of this will be referenced at renewal time.
	TokenMaxTTL time.Duration `json:"token_max_ttl" yaml:"token_max_ttl"`

	// List of policies to encode onto generated tokens. Depending on the auth method, this list may be supplemented by user/group/other values.
	TokenPolicies []string `json:"token_policies" yaml:"token_policies"`

	// List of CIDR blocks; if set, specifies blocks of IP addresses which can authenticate successfully, and ties the resulting token to these blocks as well.
	TokenBoundCIDRs []*sockaddr.SockAddrMarshaler `json:"token_bound_cidrs" yaml:"token_bound_cidrs"`

	// If set, will encode an explicit max TTL onto the token. This is a hard cap even if token_ttl and token_max_ttl would otherwise allow a renewal.
	TokenExplicitMaxTTL time.Duration `json:"token_explicit_max_ttl" yaml:"token_explicit_max_ttl"`

	// If set, the default policy will not be set on generated tokens; otherwise it will be added to the policies set in token_policies.
	TokenNoDefaultPolicy bool `json:"token_no_default_policy" yaml:"token_no_default_policy"`

	// The maximum number of times a generated token may be used (within its lifetime); 0 means unlimited. If you require the token to have the ability to create
	// child tokens, you will need to set this value to 0.
	TokenNumUses int `json:"token_num_uses" yaml:"token_num_uses"`

	// The period, if any, to set on the token.
	TokenPeriod time.Duration `json:"token_period" yaml:"token_period"`

	// The type of token that should be generated. Can be service, batch, or default to use the mount's tuned default (which unless changed will be service tokens).
	// For token store roles, there are two additional possibilities: default-service and default-batch which specify the type to return unless the client requests
	// a different type at generation time.
	TokenType string `json:"token_type" yaml:"token_type"`
}
