package google_oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleoauth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	"log"
	"net/http"
)

const ()

var oauthConfig = &oauth2.Config{
	ClientID:     clientID,
	ClientSecret: clientSecret,
	RedirectURL:  redirectURI,
	Scopes: []string{
		"openid",
		"profile",
		"email",
		"https://www.googleapis.com/auth/admin.directory.user.readonly",
		"https://www.googleapis.com/auth/admin.directory.user",
		"https://www.googleapis.com/auth/admin.directory.group",
	},
	Endpoint: google.Endpoint,
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
		<head><title>Google authentication example</title></head>
		<body>
			<h1>Google authentication</h1>
			<a href="/login">Login with Google</a>
		</body>
	</html>
	`
	fmt.Fprint(w, html)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	//u, _ := url.Parse(authUri)
	//queryParams := url.Values{}
	//queryParams.Add("response_type", "code")
	//queryParams.Add("scope", "openid profile email")
	//queryParams.Add("prompt", "consent")
	//queryParams.Add("client_id", clientID)
	//queryParams.Add("redirect_uri", redirectURI)
	//u.RawQuery = queryParams.Encode()
	//http.Redirect(w, r, u.String(), http.StatusFound)
	url := oauthConfig.AuthCodeURL(uuid.New().String(), oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	http.Redirect(w, r, url, http.StatusFound)
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
		http.Error(w, "Token exchange error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	client := oauthConfig.Client(ctx, tokenResult)

	svc, err := googleoauth.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		http.Error(w, "New Google Client error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// 获取用户信息
	userinfo, err := svc.Userinfo.Get().Do()
	if err != nil {
		http.Error(w, "Get userinfo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("✅ Google user info:\nName: %s\nEmail: %s\nPicture: %s\n", userinfo.Name, userinfo.Email, userinfo.Picture)

	adminService, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("❌ Failed to create Admin service: %v", err)
	}
	// 获取用户列表
	usersCall := adminService.Users.List().Customer("my_customer").MaxResults(10).OrderBy("email")
	usersResp, err := usersCall.Do()
	if err != nil {
		log.Fatalf("❌ Failed to get users: %v", err)
	}
	for _, u := range usersResp.Users {
		fmt.Printf("📧 %s (%s)\n", u.PrimaryEmail, u.Name.FullName)
	}

	html := fmt.Sprintf(`
	<!DOCTYPE html>
	<html>
		<body>
			<h1>sign-on successfully</h1>
			<p>Token: %s</p>
		</body>
	</html>`, tokenResult.AccessToken)
	fmt.Fprintf(w, html)
}

func getTokenResult(ctx context.Context, code string) (*oauth2.Token, error) {
	log.Printf("✅ getAccessToken code: %v \n", code)

	tokenResult, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	tokenJson, _ := json.Marshal(tokenResult)
	log.Printf("✅ GetTokenFromCode %s  \n", string(tokenJson))

	return tokenResult, nil
}
