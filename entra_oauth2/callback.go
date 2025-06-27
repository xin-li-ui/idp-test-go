package entra_oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/applicationtemplates"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

var scopes = []string{
	"Application.ReadWrite.All",
	"Directory.ReadWrite.All",
	"openid",
	"email",
	"profile",
}

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
	queryParams := url.Values{}
	queryParams.Add("response_type", "code")
	queryParams.Add("scope", strings.Join(scopes, " "))
	queryParams.Add("prompt", "consent") // approval force
	queryParams.Add("client_id", clientID)
	queryParams.Add("redirect_uri", redirectURI)
	queryParams.Add("state", "123456")
	u.RawQuery = queryParams.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Authorization code missing", http.StatusBadRequest)
		return
	}
	tokenResult, err := getTokenResult(ctx, code)
	if err != nil {
		http.Error(w, "Failed to getTokenResult: "+err.Error(), http.StatusInternalServerError)
		return
	}

	graphClient, err := NewGraphServiceClient(tokenResult)
	if err != nil {
		http.Error(w, "Failed to NewGraphServiceClient: "+err.Error(), http.StatusInternalServerError)
		return
	}

	app, sp, err := createApplication(ctx, graphClient)
	if err != nil {
		http.Error(w, "Failed to createApplication: "+err.Error(), http.StatusInternalServerError)
		return
	}

	idPConfig, err := getIdpInit(ctx)
	if err != nil {
		http.Error(w, "Failed to initIdPConfig: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = configurationSAML(ctx, graphClient, app, sp, idPConfig)
	if err != nil {
		http.Error(w, "Failed to configurationSAML: "+err.Error(), http.StatusInternalServerError)
		return
	}

	err = configurationProvisioning(ctx, graphClient, sp, idPConfig)
	if err != nil {
		http.Error(w, "Failed to configurationProvisioning: "+err.Error(), http.StatusInternalServerError)
		return
	}

	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
		<body>
			<h1>sign-on successfully</h1>
			<p>Token: %s</p>
			<p>App: %s</p>
		</body>
	</html>`, tokenResult.AccessToken, *app.GetAppId())
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

func createApplication(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient) (models.Applicationable, models.ServicePrincipalable, error) {

	// create application and ServicePrincipal
	instantiatePostRequestBody := applicationtemplates.NewItemInstantiatePostRequestBody()
	instantiatePostRequestBody.SetDisplayName(ptr("xin-auto-1234"))
	properties := make(map[string]interface{})
	properties["notes"] = "Created from template via API"
	instantiatePostRequestBody.SetAdditionalData(properties)
	templateID := "8adf8e6e-67b2-4cf2-a259-e3dc5476c621" // custom template
	result, err := graphClient.ApplicationTemplates().ByApplicationTemplateId(templateID).Instantiate().Post(ctx, instantiatePostRequestBody, nil)
	if err != nil {
		log.Fatal("Error instantiating application template:", err)
	}
	app := result.GetApplication()
	sp := result.GetServicePrincipal()
	log.Printf("✅ Application instantiated, appID: %s, appName: %s \n", *app.GetAppId(), *app.GetDisplayName())
	log.Printf("app ID: %s\n", *app.GetId())
	log.Printf("sp ID: %s\n", *sp.GetId())

	// waiting microsoft instantiate done (async)
	time.Sleep(10 * time.Second)

	return app, sp, nil
}

// Set up Single Sign-On with SAML
func configurationSAML(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, app models.Applicationable, sp models.ServicePrincipalable, idpConfig *IdpConfig) error {
	appID := app.GetId()
	spID := sp.GetId()

	// update application
	updateApp := models.NewApplication()
	web := models.NewWebApplication()
	setting := models.NewRedirectUriSettings()
	setting.SetUri(ptr(idpConfig.GetReplyURL()))
	redirectUriSettings := make([]models.RedirectUriSettingsable, 0)
	redirectUriSettings = append(redirectUriSettings, setting)
	web.SetRedirectUriSettings(redirectUriSettings)
	updateApp.SetWeb(web)
	_ = strings.ReplaceAll(uuid.New().String(), "-", "")
	updateApp.SetIdentifierUris([]string{"https://uixm.onmicrosoft.com/saml/" + idpConfig.UniqueID})
	// TODO HostNameNotOnVerifiedDomain: Values of identifierUris property must use a verified domain of the organization or its subdomain: 'https://01963312-513d-71a9-a671-275f267a4c77.idp.ui.direct/saml/xxxx'
	//app2.SetIdentifierUris([]string{idpConfig.GetEntityID()})
	// this api unsupported 'api://xxx'
	//app2.SetIdentifierUris([]string{"api://" + idpConfig.UniqueID})
	_, err := graphClient.Applications().ByApplicationId(*appID).Patch(ctx, updateApp, nil)
	if err != nil {
		log.Println("update application failed:", err)
		return err
	}
	log.Printf("✅ update application succeed: \n")

	// update ServicePrincipal
	updateSp := models.NewServicePrincipal()
	updateSp.SetPreferredSingleSignOnMode(ptr("saml"))
	samlSettings := models.NewSamlSingleSignOnSettings()
	samlSettings.SetRelayState(ptr(""))
	updateSp.SetSamlSingleSignOnSettings(samlSettings)
	updateSp.SetReplyUrls([]string{idpConfig.GetReplyURL()})
	_, err = graphClient.ServicePrincipals().ByServicePrincipalId(*spID).Patch(ctx, updateSp, nil)
	if err != nil {
		log.Fatal("update ServicePrincipal failed:", err)
	}
	log.Printf("✅ update ServicePrincipal succeed: \n")

	// add TokenSigningCertificate
	addTokenSigningCertificate := serviceprincipals.NewItemAddTokenSigningCertificatePostRequestBody()
	tokenSigningCertificate, err := graphClient.ServicePrincipals().ByServicePrincipalId(*sp.GetId()).
		AddTokenSigningCertificate().Post(ctx, addTokenSigningCertificate, nil)
	if err != nil {
		log.Println("add tokenSigningCertificate failed:", err)
		return err
	}
	log.Printf("✅ add tokenSigningCertificate succeed: %s\n", *tokenSigningCertificate.GetKeyId())

	// download XML
	outputDir := "./saml-config"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatal("Error creating output directory:", err)
	}
	outputFile := filepath.Join(outputDir, "federationmetadata.xml")
	metadataURL := fmt.Sprintf("https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml?appid=%s", "common", *sp.GetAppId())
	log.Printf("Federation Metadata URL: %s\n", metadataURL)
	resp, err := resty.New().R().
		SetOutput(outputFile).
		Get(metadataURL)
	if err != nil {
		log.Println("Error downloading federation metadata:", err)
		return err
	}
	if resp.IsSuccess() {
		log.Printf("✅ Federation Metadata XML: %s\n", outputFile)
	} else {
		return errors.New(fmt.Sprintf("Federation Metadata XML failed，code: %d", resp.StatusCode()))
	}

	// add idP
	err = addIdp(ctx, outputFile, map[string]string{
		"system_key": "office365",
		"unique_id":  idpConfig.UniqueID,
		"scim_token": idpConfig.ScimToken,
	})
	if err != nil {
		log.Println("UCS Provisioning Setup failed:", err)
		return err
	}
	log.Printf("✅ UCS Provisioning Setup \n")

	return nil
}

func configurationProvisioning(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, sp models.ServicePrincipalable, idpConfig *IdpConfig) error {
	// New provisioning configuration
	// Admin Credentials
	pair1 := models.NewSynchronizationSecretKeyStringValuePair()
	pair1.SetKey(pointer(models.BASEADDRESS_SYNCHRONIZATIONSECRET))
	pair1.SetValue(pointer(idpConfig.GetTenantURL()))
	pair2 := models.NewSynchronizationSecretKeyStringValuePair()
	pair2.SetKey(pointer(models.SECRETTOKEN_SYNCHRONIZATIONSECRET))
	pair2.SetValue(pointer(idpConfig.ScimToken))
	pairs := []models.SynchronizationSecretKeyStringValuePairable{pair1, pair2}

	// Validate Admin Credentials (Test the connection)
	validateParams := serviceprincipals.NewItemSynchronizationJobsValidateCredentialsPostRequestBody()
	validateParams.SetCredentials(pairs)
	validateParams.SetTemplateId(pointer("scim"))
	validateParams.SetUseSavedCredentials(pointer(false))
	err := graphClient.ServicePrincipals().ByServicePrincipalId(*sp.GetId()).
		Synchronization().Jobs().ValidateCredentials().Post(ctx, validateParams, nil)
	if err != nil {
		log.Println("Validate Credentials (Test the connection) failed:", err)
		return err
	}
	log.Printf("✅ Validate Credentials (Test the connection) succeed\n")

	// create job
	synchronizationJob := models.NewSynchronizationJob()
	synchronizationJob.SetTemplateId(pointer("scim"))
	createdJob, err := graphClient.ServicePrincipals().ByServicePrincipalId(*sp.GetId()).
		Synchronization().Jobs().Post(ctx, synchronizationJob, nil)
	if err != nil {
		log.Println("New SynchronizationJob failed:", err)
		return err
	}
	log.Printf("✅ New SynchronizationJob succeed: %s\n", *createdJob.GetId())
	// waiting job create done (async)
	time.Sleep(5 * time.Second)

	// New provisioning configuration
	pair3 := models.NewSynchronizationSecretKeyStringValuePair()
	pair3.SetKey(pointer(models.SYNCNOTIFICATIONSETTINGS_SYNCHRONIZATIONSECRET))
	pair3.SetValue(pointer("{\"Enabled\":false,\"DeleteThresholdEnabled\":false,\"HumanResourcesLookaheadQueryEnabled\":false}"))
	pair4 := models.NewSynchronizationSecretKeyStringValuePair()
	pair4.SetKey(pointer(models.SYNCALL_SYNCHRONIZATIONSECRET))
	pair4.SetValue(pointer("false"))
	pairs = append(pairs, pair3, pair4)
	addCredParams := serviceprincipals.NewItemSynchronizationSecretsPutRequestBody()
	addCredParams.SetValue(pairs)
	_, err = graphClient.ServicePrincipals().ByServicePrincipalId(*sp.GetId()).
		Synchronization().Secrets().PutAsSecretsPutResponse(ctx, addCredParams, nil)
	if err != nil {
		log.Println("New provisioning configuration failed:", err)
		return err
	}
	log.Printf("✅ New provisioning configuration succeed\n")
	time.Sleep(5 * time.Second)

	// start job
	err = graphClient.ServicePrincipals().ByServicePrincipalId(*sp.GetId()).
		Synchronization().Jobs().BySynchronizationJobId(*createdJob.GetId()).Start().Post(ctx, nil)
	if err != nil {
		log.Fatal("Start SynchronizationJob failed:", err)
	}
	log.Printf("✅ Start SynchronizationJob succeed\n")
	return nil
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

func ptr(s string) *string {
	return &s
}

func pointer[T any](v T) *T {
	return &v
}
