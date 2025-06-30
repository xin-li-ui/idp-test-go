package entra_oauth2

import (
	"context"
	"fmt"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/serviceprincipals"
	"log"
	"time"
)

func configurationProvisioning(ctx context.Context, sp models.ServicePrincipalable, idpConfig *IdpConfig) error {
	spID := sp.GetId()

	// 第一步：验证管理员凭据
	if err := validateCredentials(ctx, *spID, idpConfig); err != nil {
		return fmt.Errorf("验证管理员凭据失败: %w", err)
	}

	// 第二步：创建同步作业
	job, err := createSynchronizationJob(ctx, *spID)
	if err != nil {
		return fmt.Errorf("创建同步作业失败: %w", err)
	}

	// 第三步：等待作业创建完成
	if err = waitForJobReady(ctx, *spID, *job.GetId()); err != nil {
		return fmt.Errorf("等待同步作业就绪失败: %w", err)
	}

	// 第四步：配置同步设置
	if err := configureSync(ctx, *spID, idpConfig); err != nil {
		return fmt.Errorf("配置同步设置失败: %w", err)
	}

	// 第五步：启动同步作业
	if err := startSynchronizationJob(ctx, *spID, *job.GetId()); err != nil {
		return fmt.Errorf("启动同步作业失败: %w", err)
	}
	return nil
}

func validateCredentials(ctx context.Context, spID string, idpConfig *IdpConfig) error {
	log.Printf("🔍 验证管理员凭据")

	// 准备凭据
	pair1 := models.NewSynchronizationSecretKeyStringValuePair()
	pair1.SetKey(pointer(models.BASEADDRESS_SYNCHRONIZATIONSECRET))
	pair1.SetValue(pointer(idpConfig.GetTenantURL()))

	pair2 := models.NewSynchronizationSecretKeyStringValuePair()
	pair2.SetKey(pointer(models.SECRETTOKEN_SYNCHRONIZATIONSECRET))
	pair2.SetValue(pointer(idpConfig.ScimToken))

	pairs := []models.SynchronizationSecretKeyStringValuePairable{pair1, pair2}

	// 创建验证请求
	validateParams := serviceprincipals.NewItemSynchronizationJobsValidateCredentialsPostRequestBody()
	validateParams.SetCredentials(pairs)
	validateParams.SetTemplateId(pointer("scim"))
	validateParams.SetUseSavedCredentials(pointer(false))

	// 验证凭据
	err := graphClient.ServicePrincipals().ByServicePrincipalId(spID).
		Synchronization().Jobs().ValidateCredentials().Post(ctx, validateParams, nil)
	if err != nil {
		return fmt.Errorf("验证凭据失败: %w", err)
	}

	log.Printf("✅ 管理员凭据验证成功")
	return nil
}

// createSynchronizationJob 创建同步作业
func createSynchronizationJob(ctx context.Context, spID string) (models.SynchronizationJobable, error) {
	log.Printf("🔄 创建同步作业")

	synchronizationJob := models.NewSynchronizationJob()
	synchronizationJob.SetTemplateId(pointer("scim"))

	createdJob, err := graphClient.ServicePrincipals().ByServicePrincipalId(spID).
		Synchronization().Jobs().Post(ctx, synchronizationJob, nil)
	if err != nil {
		return nil, fmt.Errorf("创建同步作业失败: %w", err)
	}

	log.Printf("✅ 同步作业创建成功: %s", *createdJob.GetId())
	return createdJob, nil
}

// waitForJobReady 等待同步作业就绪
func waitForJobReady(ctx context.Context, spID, jobID string) error {
	log.Printf("⏳ 等待同步作业就绪...")

	timeoutCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	startTime := time.Now()

	for {
		select {
		case <-timeoutCtx.Done():
			return fmt.Errorf("等待同步作业就绪超时，已等待 %v", time.Since(startTime))

		case <-ticker.C:
			ready, err := checkJobReady(ctx, spID, jobID)
			if err != nil {
				log.Printf("⚠️  检查同步作业状态时出错: %v", err)
				continue
			}

			if ready {
				elapsed := time.Since(startTime)
				log.Printf("✅ 同步作业已就绪，耗时: %v", elapsed)
				return nil
			}

			log.Printf("🔄 同步作业尚未就绪，继续等待... (已等待 %v)", time.Since(startTime))
		}
	}
}

// checkJobReady 检查同步作业是否就绪
func checkJobReady(ctx context.Context, spID, jobID string) (bool, error) {
	// 尝试获取同步作业
	job, err := graphClient.ServicePrincipals().ByServicePrincipalId(spID).
		Synchronization().Jobs().BySynchronizationJobId(jobID).Get(ctx, nil)
	if err != nil {
		log.Printf("🔍 无法获取同步作业: %v", err)
		return false, nil
	}

	// 检查作业状态
	if job.GetId() == nil {
		return false, nil
	}

	// 尝试获取作业的详细信息来确认其完全就绪
	_, err = graphClient.ServicePrincipals().ByServicePrincipalId(spID).
		Synchronization().Jobs().BySynchronizationJobId(jobID).Schema().Get(ctx, nil)
	if err != nil {
		log.Printf("🔍 同步作业模式不可用: %v", err)
		return false, nil
	}

	return true, nil
}

// configureSync 配置同步设置
func configureSync(ctx context.Context, spID string, idpConfig *IdpConfig) error {
	log.Printf("🔧 配置同步设置")

	// 准备所有凭据
	pair1 := models.NewSynchronizationSecretKeyStringValuePair()
	pair1.SetKey(pointer(models.BASEADDRESS_SYNCHRONIZATIONSECRET))
	pair1.SetValue(pointer(idpConfig.GetTenantURL()))

	pair2 := models.NewSynchronizationSecretKeyStringValuePair()
	pair2.SetKey(pointer(models.SECRETTOKEN_SYNCHRONIZATIONSECRET))
	pair2.SetValue(pointer(idpConfig.ScimToken))

	pair3 := models.NewSynchronizationSecretKeyStringValuePair()
	pair3.SetKey(pointer(models.SYNCNOTIFICATIONSETTINGS_SYNCHRONIZATIONSECRET))
	pair3.SetValue(pointer("{\"Enabled\":false,\"DeleteThresholdEnabled\":false,\"HumanResourcesLookaheadQueryEnabled\":false}"))

	pair4 := models.NewSynchronizationSecretKeyStringValuePair()
	pair4.SetKey(pointer(models.SYNCALL_SYNCHRONIZATIONSECRET))
	pair4.SetValue(pointer("false"))

	pairs := []models.SynchronizationSecretKeyStringValuePairable{pair1, pair2, pair3, pair4}

	// 应用配置
	addCredParams := serviceprincipals.NewItemSynchronizationSecretsPutRequestBody()
	addCredParams.SetValue(pairs)

	_, err := graphClient.ServicePrincipals().ByServicePrincipalId(spID).
		Synchronization().Secrets().PutAsSecretsPutResponse(ctx, addCredParams, nil)
	if err != nil {
		return fmt.Errorf("应用同步配置失败: %w", err)
	}

	log.Printf("✅ 同步设置配置成功")
	return nil
}

// startSynchronizationJob 启动同步作业
func startSynchronizationJob(ctx context.Context, spID, jobID string) error {
	log.Printf("🚀 启动同步作业")

	err := graphClient.ServicePrincipals().ByServicePrincipalId(spID).
		Synchronization().Jobs().BySynchronizationJobId(jobID).Start().Post(ctx, nil)
	if err != nil {
		return fmt.Errorf("启动同步作业失败: %w", err)
	}

	log.Printf("✅ 同步作业启动成功")
	return nil
}
