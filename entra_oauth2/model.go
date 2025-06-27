package entra_oauth2

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"time"
)

type TokenCredential struct {
	Token     string
	ExpiresOn time.Time
	RefreshOn time.Time
}

func (t *TokenCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{
		Token:     t.Token,
		ExpiresOn: t.ExpiresOn,
		RefreshOn: t.RefreshOn,
	}, nil
}

type IdpInitDataResp struct {
	Data *IdpConfig `json:"data"`
}

type IdpConfig struct {

	// org proxy
	OrgProxy bool `json:"org_proxy"`

	// org proxy domain
	OrgProxyDomain string `json:"org_proxy_domain"`

	// path acs endpoint
	PathAcsEndpoint string `json:"path_acs_endpoint"`

	// path entity id
	PathEntityID string `json:"path_entity_id"`

	// path tenant url
	PathTenantURL string `json:"path_tenant_url"`

	// scim token
	ScimToken string `json:"scim_token"`

	// unique id
	UniqueID string `json:"unique_id"`
}

func (idpConfig *IdpConfig) GetEntityID() string {
	return "https://" + idpConfig.OrgProxyDomain + idpConfig.PathEntityID
}
func (idpConfig *IdpConfig) GetReplyURL() string {
	return "https://" + idpConfig.OrgProxyDomain + idpConfig.PathAcsEndpoint
}
func (idpConfig *IdpConfig) GetTenantURL() string {
	return "https://" + idpConfig.OrgProxyDomain + idpConfig.PathTenantURL
}
