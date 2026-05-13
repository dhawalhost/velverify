package directory

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// StartAccountErasureWorker starts a background goroutine that periodically
// polls for users in pending_deletion status whose updated_at timestamp is older
// than the retention period, and permanently deletes them.
func StartAccountErasureWorker(ctx context.Context, svc Service, log *zap.Logger, checkInterval time.Duration, retentionPeriod time.Duration) {
	ticker := time.NewTicker(checkInterval)
	go func() {
		defer ticker.Stop()
		log.Info("Account erasure worker started", zap.Duration("check_interval", checkInterval), zap.Duration("retention_period", retentionPeriod))
		for {
			select {
			case <-ctx.Done():
				log.Info("Account erasure worker stopping")
				return
			case <-ticker.C:
				runAccountErasureJob(ctx, svc, log, retentionPeriod)
			}
		}
	}()
}

func runAccountErasureJob(ctx context.Context, svc Service, log *zap.Logger, retentionPeriod time.Duration) {
	olderThan := time.Now().Add(-retentionPeriod)
	users, err := svc.ListPendingDeletions(ctx, olderThan)
	if err != nil {
		log.Error("Failed to list pending deletions", zap.Error(err))
		return
	}

	if len(users) == 0 {
		return
	}

	log.Info("Starting account erasure job", zap.Int("pending_users_count", len(users)))

	for _, user := range users {
		log.Info("Permanently erasing account", zap.String("user_id", user.ID), zap.String("tenant_id", user.TenantID))
		if err := svc.DeleteUser(ctx, user.TenantID, user.ID); err != nil {
			log.Error("Failed to permanently delete user", zap.String("user_id", user.ID), zap.Error(err))
		}
	}
}
