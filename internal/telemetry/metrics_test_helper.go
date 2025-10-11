package telemetry

import (
	"sync"
	"time"
)

func resetMetricsForTest() {
	initOnce = sync.Once{}
	obsOnce = sync.Once{}
	proxyObsOnce = sync.Once{}
	obsStopper = nil
	proxyStopper = nil
	if wsConnStopper != nil {
		wsConnStopper()
	}
	wsConnStopper = nil
	meter = nil

	mSiteRegistrations = nil
	mSiteOnline = nil
	mSiteLastHeartbeat = nil

	mTunnelSessions = nil
	mTunnelBytes = nil
	mTunnelLatency = nil
	mReconnects = nil

	mConnAttempts = nil
	mConnErrors = nil

	mConfigReloads = nil
	mConfigApply = nil
	mCertRotationTotal = nil
	mProcessStartTime = nil

	mBuildInfo = nil

	mWSConnectLatency = nil
	mWSMessages = nil
	mWSDisconnects = nil
	mWSKeepaliveFailure = nil
	mWSSessionDuration = nil
	mWSConnected = nil
	mWSReconnects = nil

	mProxyActiveConns = nil
	mProxyBufferBytes = nil
	mProxyAsyncBacklogByte = nil
	mProxyDropsTotal = nil
	mProxyAcceptsTotal = nil
	mProxyConnDuration = nil
	mProxyConnectionsTotal = nil

	processStartUnix = float64(time.Now().UnixNano()) / 1e9
	wsConnectedState.Store(0)
	includeTunnelIDVal.Store(false)
	includeSiteLabelVal.Store(false)
}
