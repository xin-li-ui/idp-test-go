package entra_oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"log"
	"net/http"
	"net/url"
	"strings"
)

const (
	clientID     = "a91fb3d8-8d87-4ed9-9076-585b1b152709"     // from bootstrap app (company tenant)
	clientSecret = "ABs8Q~h5Kg93k0QaESxzTKaJ5SX8tOTLprtXlbE3" // from bootstrap app (company tenant)
	redirectURI  = "http://localhost:8080/auth/callback"      // configured in bootstrap app (company tenant)

	authUri      = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	tokenUri     = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	defaultScope = "https://graph.microsoft.com/.default"
)

var scopes = []string{
	"Application.ReadWrite.All",
	"Directory.Read.All",
	//"openid",
	//"email",
	//"profile",
}
var graphClient *msgraphsdkgo.GraphServiceClient
var tokenResult *confidential.AuthResult
var stateMap = map[string]string{}

func CallbackMethod() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/auth/callback", handleCallback)

	port := "8080"
	log.Printf("Server running on http://localhost:%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
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

func handleLogin(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(authUri)
	if err != nil {
		http.Error(w, "Parse failed", http.StatusBadRequest)
		return
	}
	state := uuid.New().String()
	queryParams := url.Values{}
	queryParams.Add("response_type", "code")
	queryParams.Add("scope", strings.Join(scopes, " "))
	queryParams.Add("prompt", "consent") // approval force
	queryParams.Add("client_id", clientID)
	queryParams.Add("redirect_uri", redirectURI)
	queryParams.Add("state", state)
	u.RawQuery = queryParams.Encode()
	stateMap[state] = state
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {

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
	if _, ok := stateMap[state]; ok {
		delete(stateMap, state)
	} else {
		http.Error(w, "state not exist", http.StatusBadRequest)
		return
	}

	var err error
	tokenResult, err = getTokenResult(ctx, code)
	if err != nil {
		http.Error(w, "Failed to getTokenResult: "+err.Error(), http.StatusInternalServerError)
		return
	}

	//graphClient, err = NewGraphServiceClient()
	//if err != nil {
	//	http.Error(w, "Failed to NewGraphServiceClient: "+err.Error(), http.StatusInternalServerError)
	//	return
	//}
	//
	//app, sp, err := createApplication(ctx)
	//if err != nil {
	//	http.Error(w, "Failed to createApplication: "+err.Error(), http.StatusInternalServerError)
	//	return
	//}
	//
	//idPConfig, err := getIdpInit(ctx)
	//if err != nil {
	//	http.Error(w, "Failed to initIdPConfig: "+err.Error(), http.StatusInternalServerError)
	//	return
	//}
	//
	//err = configurationSAML(ctx, app, sp, idPConfig)
	//if err != nil {
	//	http.Error(w, "Failed to configurationSAML: "+err.Error(), http.StatusInternalServerError)
	//	return
	//}
	//
	//err = configurationProvisioning(ctx, sp, idPConfig)
	//if err != nil {
	//	http.Error(w, "Failed to configurationProvisioning: "+err.Error(), http.StatusInternalServerError)
	//	return
	//}

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

func getTokenResult(ctx context.Context, code string) (*confidential.AuthResult, error) {
	log.Printf("✅ getAccessToken code: %v \n", code)

	cred, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		return nil, err
	}
	client, err := confidential.New("https://login.microsoftonline.com/common", clientID, cred)
	if err != nil {
		return nil, err
	}
	tokenResult, err := client.AcquireTokenByAuthCode(ctx, code, redirectURI, scopes)
	if err != nil {
		return nil, err
	}
	tokenJson, _ := json.Marshal(tokenResult)
	log.Printf("✅ GetTokenFromCode %s  \n", string(tokenJson))

	return &tokenResult, nil
}

func getTokenResult2(ctx context.Context, code string) (map[string]interface{}, error) {
	log.Printf("✅ getAccessToken2 code: %v \n", code)

	formData := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
		"scope":         "openid Application.ReadWrite.All",
	}
	resp, err := resty.New().R().
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

func getIdpInit(ctx context.Context) (idpConfig *IdpConfig, err error) {
	result := &IdpInitDataResp{}
	client := resty.New()
	_, err = client.R().SetContext(ctx).
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

func addIdp(ctx context.Context, filePath string, formData map[string]string) (err error) {
	//	{
	//		"system_key": "office365",
	//		"unique_id": "",
	//		"scim_token": "",
	//	}
	client := resty.New()
	_, err = client.R().SetContext(ctx).
		SetFile("metadata", filePath).
		SetFormData(formData).
		Post("http://192.168.1.1:9580/proxy/directory/idp/identity_provider")
	if err != nil {
		return
	}
	log.Printf("✅ Add idpConfig  \n")
	return
}

func NewGraphServiceClient() (*msgraphsdkgo.GraphServiceClient, error) {
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
