package entra_oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/patrickmn/go-cache"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	clientID     = "a91fb3d8-8d87-4ed9-9076-585b1b152709"     // from bootstrap app (company tenant)
	clientSecret = "ABs8Q~h5Kg93k0QaESxzTKaJ5SX8tOTLprtXlbE3" // from bootstrap app (company tenant)
	redirectURI  = "http://localhost:8080/auth/callback"      // configured in bootstrap app (company tenant)

	authUri      = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	tokenUri     = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	defaultScope = "https://graph.microsoft.com/.default"
)

type EntraService struct {
	scopes       []string
	graphClient  *msgraphsdkgo.GraphServiceClient
	stateCache   *cache.Cache
	stateToToken map[string]*confidential.AuthResult
	httpClient   *resty.Client
}

func NewEntraService() *EntraService {
	s := &EntraService{
		scopes: []string{
			"Application.ReadWrite.All",
			//"Directory.ReadWrite.All",
			//"openid",
			//"email",
			//"profile",
		},
		stateCache:   cache.New(5*time.Minute, 10*time.Minute),
		stateToToken: make(map[string]*confidential.AuthResult),
		httpClient:   resty.New(),
	}
	return s
}

func (s *EntraService) HandleHome(w http.ResponseWriter, r *http.Request) {
	html := `
	<!DOCTYPE html>
	<html>
		<head><title>Microsoft authentication example</title></head>
		<body>
			<h1>Microsoft authentication example</h1>
			<a href="/login">Microsoft Entra</a>
		</body>
	</html>
	`
	fmt.Fprint(w, html)
}

func (s *EntraService) HandleLogin(w http.ResponseWriter, r *http.Request) {

	// build auth url
	u, err := url.Parse(authUri)
	if err != nil {
		http.Error(w, "Parse failed", http.StatusBadRequest)
		return
	}
	state := uuid.New().String()
	queryParams := url.Values{}
	queryParams.Add("response_type", "code")
	queryParams.Add("scope", strings.Join(s.scopes, " "))
	queryParams.Add("prompt", "consent") // approval force
	queryParams.Add("client_id", clientID)
	queryParams.Add("redirect_uri", redirectURI)
	queryParams.Add("state", state)
	u.RawQuery = queryParams.Encode()

	// save state
	s.setState(state)

	// notify state to ucs
	go func() {
		ctx := context.TODO()
		_, err = s.httpClient.R().SetContext(ctx).
			SetBody(map[string]interface{}{
				"state":      state,
				"expired_at": time.Now().Add(5 * time.Minute).Unix(),
			}).
			Post("http://192.168.1.1:9580/admin/api/v1/auth/entra_state")
		if err != nil {
			log.Printf("save entra state failed: %v \n", state)
			return
		}
	}()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *EntraService) HandleCallback(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code missing", http.StatusBadRequest)
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "state missing", http.StatusBadRequest)
		return
	}
	if s.existState(state) {
		s.deleteState(state)
	} else {
		http.Error(w, "state not exist", http.StatusBadRequest)
		return
	}

	var err error
	tokenResult, err := s.getTokenResult(ctx, code)
	if err != nil {
		http.Error(w, "Failed to getTokenResult: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.stateToToken[state] = tokenResult

	go func() {
		bctx := context.TODO()

		// notify token to ucs
		_, err = s.httpClient.R().SetContext(bctx).
			SetBody(map[string]interface{}{
				"access_token": tokenResult.AccessToken,
				"expires_on":   tokenResult.ExpiresOn.Unix(),
				"account": map[string]string{
					"username": tokenResult.Account.PreferredUsername,
				},
			}).
			Post("http://192.168.1.1:9580/admin/api/v1/auth/entra_token")
		if err != nil {
			log.Printf("save entra token failed: %v \n", state)
			return
		}

		//graphClient, err := NewGraphServiceClient(tokenResult)
		//if err != nil {
		//	log.Printf("Failed to NewGraphServiceClient: " + err.Error())
		//	return
		//}
		//s.graphClient = graphClient
		//
		//app, sp, err := s.createApplication(bctx)
		//if err != nil {
		//	log.Printf("Failed to createApplication: " + err.Error())
		//	return
		//}
		//
		//idPConfig, err := s.getIdpInit(bctx)
		//if err != nil {
		//	log.Printf("Failed to initIdPConfig: " + err.Error())
		//	return
		//}
		//
		//err = s.configurationSAML(bctx, app, sp, idPConfig, tokenResult)
		//if err != nil {
		//	log.Printf("Failed to configurationSAML: " + err.Error())
		//	return
		//}
		//
		//err = s.configurationProvisioning(bctx, sp, idPConfig)
		//if err != nil {
		//	log.Printf("Failed to configurationProvisioning: " + err.Error())
		//	return
		//}
	}()

	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
		<body>
			<h1>successfully</h1>
			<p>Token: %s</p>
		</body>
	</html>`, tokenResult.AccessToken)
	fmt.Fprintf(w, html)
}

// request from ucs
// [GET] /test/token
func (s *EntraService) GetToken(w http.ResponseWriter, r *http.Request) {

	state := r.URL.Query().Get("state")
	if state == "" {
		http.Error(w, "state missing", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	tokenResult, exist := s.stateToToken[state]
	if !exist {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{}"))
		return
	}

	response := EntraToken{
		AccessToken: tokenResult.AccessToken,
		ExpiresOn:   tokenResult.ExpiresOn.Unix(),
	}
	response.Account.Username = tokenResult.Account.PreferredUsername
	jsonData, _ := json.Marshal(response)
	w.WriteHeader(http.StatusOK)
	w.Write(jsonData)
}

func (s *EntraService) getTokenResult(ctx context.Context, code string) (*confidential.AuthResult, error) {
	log.Printf("✅ getAccessToken code: %v \n", code)

	cred, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		return nil, err
	}
	client, err := confidential.New("https://login.microsoftonline.com/common", clientID, cred)
	if err != nil {
		return nil, err
	}
	tokenResult, err := client.AcquireTokenByAuthCode(ctx, code, redirectURI, s.scopes)
	if err != nil {
		return nil, err
	}
	tokenJson, _ := json.Marshal(tokenResult)
	log.Printf("✅ GetTokenFromCode %s  \n", string(tokenJson))

	return &tokenResult, nil
}

func (s *EntraService) getTokenResult2(ctx context.Context, code string) (map[string]interface{}, error) {
	log.Printf("✅ getAccessToken2 code: %v \n", code)

	formData := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
		"scope":         "openid Application.ReadWrite.All",
	}
	resp, err := s.httpClient.R().
		SetFormData(formData).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Post(tokenUri)
	if err != nil {
		return nil, err
	}
	result := make(map[string]interface{})
	if err := json.Unmarshal(resp.Body(), &result); err != nil {
		return nil, err
	}
	tokenJson, _ := json.Marshal(result)
	log.Printf("✅ GetTokenFromCode2 %s  \n", string(tokenJson))
	return result, nil
}

func (s *EntraService) getIdpInit(ctx context.Context) (idpConfig *IdpConfig, err error) {
	result := &IdpInitDataResp{}
	_, err = s.httpClient.R().SetContext(ctx).
		SetResult(&result).
		Get("http://192.168.1.1:9580/proxy/directory/idp/identity_provider/init")
	if err != nil {
		log.Println("getIdpInit failed:", err)
		return
	}
	idpConfig = result.Data
	idpConfigJson, _ := json.Marshal(idpConfig)
	log.Printf("✅ Init idpConfig %s  \n", string(idpConfigJson))
	return
}

func (s *EntraService) addIdp(ctx context.Context, filePath string, formData map[string]string) (err error) {
	//	{
	//		"system_key": "office365",
	//		"unique_id": "",
	//		"scim_token": "",
	//	}
	_, err = s.httpClient.R().SetContext(ctx).
		SetFile("metadata", filePath).
		SetFormData(formData).
		Post("http://192.168.1.1:9580/proxy/directory/idp/identity_provider")
	if err != nil {
		return
	}
	log.Printf("✅ Add idpConfig  \n")
	return
}

func NewGraphServiceClient(tokenResult *confidential.AuthResult) (*msgraphsdkgo.GraphServiceClient, error) {
	credential := &TokenCredential{
		Token:     tokenResult.AccessToken,
		ExpiresOn: tokenResult.ExpiresOn,
		RefreshOn: tokenResult.Metadata.RefreshOn,
	}

	// 创建Graph客户端
	graphClient, err := msgraphsdkgo.NewGraphServiceClientWithCredentials(credential, []string{})
	if err != nil {
		return nil, fmt.Errorf("创建Graph客户端失败: %v", err)
	}

	return graphClient, nil
}

func pointer[T any](v T) *T {
	return &v
}

func (s *EntraService) existState(state string) bool {
	_, exist := s.stateCache.Get(state)
	return exist
}

func (s *EntraService) setState(state string) {
	s.stateCache.SetDefault(state, state)
}

func (s *EntraService) deleteState(state string) {
	s.stateCache.Delete(state)
}
