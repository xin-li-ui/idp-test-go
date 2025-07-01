package entra_oauth2

import (
	"context"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/applicationtemplates"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func createApplication(ctx context.Context) (models.Applicationable, models.ServicePrincipalable, error) {

	log.Printf("🔄 开始创建应用程序")

	// 第一步：实例化应用程序模板
	app, sp, err := instantiateApplicationTemplate(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("实例化应用程序模板失败: %w", err)
	}

	log.Printf("✅ 应用程序模板实例化成功")
	log.Printf("📋 App ID: %s, SP ID: %s", *app.GetId(), *sp.GetId())

	// 第二步：等待应用程序完全创建完成
	if err := waitForApplicationReady(ctx, app, sp); err != nil {
		return nil, nil, fmt.Errorf("等待应用程序就绪失败: %w", err)
	}

	log.Printf("✅ 应用程序创建完成并就绪")
	return app, sp, nil
}

// instantiateApplicationTemplate 实例化应用程序模板
func instantiateApplicationTemplate(ctx context.Context) (models.Applicationable, models.ServicePrincipalable, error) {
	// 创建实例化请求
	instantiatePostRequestBody := applicationtemplates.NewItemInstantiatePostRequestBody()

	// 生成唯一的显示名称
	instantiatePostRequestBody.SetDisplayName(pointer("xin-auto-1234"))

	// 添加附加属性
	properties := make(map[string]interface{})
	properties["notes"] = fmt.Sprintf("Created via API at %s", time.Now().Format(time.RFC3339))
	instantiatePostRequestBody.SetAdditionalData(properties)

	// 调用API创建应用程序
	templateID := "8adf8e6e-67b2-4cf2-a259-e3dc5476c621" // custom template
	result, err := graphClient.ApplicationTemplates().
		ByApplicationTemplateId(templateID).
		Instantiate().
		Post(ctx, instantiatePostRequestBody, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("调用实例化API失败: %w", err)
	}

	app := result.GetApplication()
	sp := result.GetServicePrincipal()

	if app == nil {
		return nil, nil, fmt.Errorf("应用程序对象为空")
	}
	if sp == nil {
		return nil, nil, fmt.Errorf("服务主体对象为空")
	}

	return app, sp, nil
}

func waitForApplicationReady(ctx context.Context, app models.Applicationable, sp models.ServicePrincipalable) error {
	log.Printf("⏳ 等待应用程序完全就绪...")

	// 创建带超时的上下文
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	for {
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("等待应用程序就绪超时，已等待 %v", time.Since(startTime))
		case <-ticker.C:
			// 检查应用程序是否就绪
			ready, err := checkApplicationReady(ctx, app, sp)
			if err != nil {
				log.Printf("⚠️  检查应用程序状态时出错: %v", err)
				continue
			}

			if ready {
				elapsed := time.Since(startTime)
				log.Printf("✅ 应用程序已就绪，耗时: %v", elapsed)
				return nil
			}

			log.Printf("🔄 应用程序尚未就绪，继续等待... (已等待 %v)", time.Since(startTime))
		}
	}
}

func checkApplicationReady(ctx context.Context, app models.Applicationable, sp models.ServicePrincipalable) (bool, error) {
	appID := app.GetId()
	spID := sp.GetId()

	if appID == nil || spID == nil {
		return false, fmt.Errorf("应用程序或服务主体ID为空")
	}

	// 检查1：尝试读取应用程序
	if !checkApplicationAccessible(ctx, *appID) {
		return false, nil
	}

	// 检查2：尝试读取服务主体
	if !checkServicePrincipalAccessible(ctx, *spID) {
		return false, nil
	}

	// 检查3：尝试更新应用程序（测试写权限）
	if !checkApplicationUpdatable(ctx, *appID) {
		return false, nil
	}

	// 所有检查都通过
	return true, nil
}

func checkApplicationAccessible(ctx context.Context, appID string) bool {
	_, err := graphClient.Applications().ByApplicationId(appID).Get(ctx, nil)
	if err != nil {
		log.Printf("🔍 应用程序不可访问: %v", err)
		return false
	}
	return true
}

// checkServicePrincipalAccessible 检查服务主体是否可访问
func checkServicePrincipalAccessible(ctx context.Context, spID string) bool {
	_, err := graphClient.ServicePrincipals().ByServicePrincipalId(spID).Get(ctx, nil)
	if err != nil {
		log.Printf("🔍 服务主体不可访问: %v", err)
		return false
	}
	return true
}

// checkApplicationUpdatable 检查应用程序是否可更新
func checkApplicationUpdatable(ctx context.Context, appID string) bool {
	// 创建一个简单的更新操作来测试
	updateApp := models.NewApplication()
	updateApp.SetNotes(pointer(fmt.Sprintf("Readiness check at %s", time.Now().Format(time.RFC3339))))

	_, err := graphClient.Applications().ByApplicationId(appID).Patch(ctx, updateApp, nil)
	if err != nil {
		log.Printf("🔍 应用程序不可更新: %v", err)
		return false
	}
	return true
}

// Set up Single Sign-On with SAML
func configurationSAML(ctx context.Context, app models.Applicationable, sp models.ServicePrincipalable, idpConfig *IdpConfig) error {
	appID := app.GetId()
	spID := sp.GetId()

	// update application
	updateApp := models.NewApplication()
	setting := models.NewRedirectUriSettings()
	setting.SetUri(pointer(idpConfig.GetReplyURL()))
	web := models.NewWebApplication()
	web.SetRedirectUriSettings([]models.RedirectUriSettingsable{setting})
	updateApp.SetWeb(web)
	domain := strings.Split(tokenResult.Account.PreferredUsername, "@")[1]
	orgID := uuid.New().String()
	updateApp.SetIdentifierUris([]string{fmt.Sprintf("https://%s/saml/%s", domain, orgID)})
	// TODO HostNameNotOnVerifiedDomain: Values of identifierUris property must use a verified domain of the organization or its subdomain: 'https://01963312-513d-71a9-a671-275f267a4c77.idp.ui.direct/saml/xxxx'
	//updateApp.SetIdentifierUris([]string{idpConfig.GetEntityID()})
	// this api unsupported 'api://xxx'
	//updateApp.SetIdentifierUris([]string{"api://" + idpConfig.UniqueID})
	_, err := graphClient.Applications().ByApplicationId(*appID).Patch(ctx, updateApp, nil)
	if err != nil {
		return fmt.Errorf("update application failed: %s", err.Error())
	}
	log.Printf("✅ update application succeed \n")

	// update ServicePrincipal
	updateSp := models.NewServicePrincipal()
	updateSp.SetPreferredSingleSignOnMode(pointer("saml"))
	samlSettings := models.NewSamlSingleSignOnSettings()
	samlSettings.SetRelayState(pointer(""))
	updateSp.SetSamlSingleSignOnSettings(samlSettings)
	updateSp.SetReplyUrls([]string{idpConfig.GetReplyURL()})
	_, err = graphClient.ServicePrincipals().ByServicePrincipalId(*spID).Patch(ctx, updateSp, nil)
	if err != nil {
		return fmt.Errorf("update ServicePrincipal failed: %s", err.Error())
	}
	log.Printf("✅ update ServicePrincipal succeed \n")

	// SAML Certificates - add TokenSigningCertificate
	addTokenSigningCertificate := serviceprincipals.NewItemAddTokenSigningCertificatePostRequestBody()
	tokenSigningCertificate, err := graphClient.ServicePrincipals().ByServicePrincipalId(*sp.GetId()).
		AddTokenSigningCertificate().Post(ctx, addTokenSigningCertificate, nil)
	if err != nil {
		return fmt.Errorf("add tokenSigningCertificate failed: %s", err.Error())
	}
	log.Printf("✅ add tokenSigningCertificate succeed: %s\n", *tokenSigningCertificate.GetKeyId())

	// download XML
	outputDir := "./saml-config"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatal("Error creating output directory:", err)
	}
	outputFile := filepath.Join(outputDir, "federationmetadata.xml")
	metadataURL := fmt.Sprintf("https://login.microsoftonline.com/common/federationmetadata/2007-06/federationmetadata.xml?appid=%s", *sp.GetAppId())
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
