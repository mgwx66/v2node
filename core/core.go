package core

import (
	"encoding/json"
	"sync"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/core/app/dispatcher"
	_ "github.com/wyx2685/v2node/core/distro/all"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

type AddUsersParams struct {
	Tag   string
	Users []panel.UserInfo
	*panel.NodeInfo
}

type V2Core struct {
	access     sync.Mutex
	Server     *core.Instance
	ConfigDir  string
	users      *UserMap
	ihm        inbound.Manager
	ohm        outbound.Manager
	dispatcher *dispatcher.DefaultDispatcher
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(ConfigDir string) *V2Core {
	core := &V2Core{
		ConfigDir: ConfigDir,
		users: &UserMap{
			uidMap: make(map[string]int),
		},
	}
	return core
}

func (v *V2Core) Start(c *conf.Conf) error {
	v.access.Lock()
	defer v.access.Unlock()
	v.Server = getCore(c)
	if err := v.Server.Start(); err != nil {
		return err
	}
	v.ihm = v.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	v.ohm = v.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	v.dispatcher = v.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	return nil
}

func (v *V2Core) Close() error {
	v.access.Lock()
	defer v.access.Unlock()
	v.ihm = nil
	v.ohm = nil
	v.dispatcher = nil
	err := v.Server.Close()
	if err != nil {
		return err
	}
	return nil
}

func getCore(c *conf.Conf) *core.Instance {
	// Log Config
	access_output := "none"
	if c.LogConfig.Output != "" {
		access_output = c.LogConfig.Output
	}
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: access_output,
		ErrorLog:  c.LogConfig.Output,
	}
	// DNS config
	coreDnsConfig := &coreConf.DNSConfig{}
	dnsConfig, _ := coreDnsConfig.Build()
	// Routing config
	coreRouterConfig := &coreConf.RouterConfig{}
	routeConfig, _ := coreRouterConfig.Build()
	// Inbound config
	var inBoundConfig []*core.InboundHandlerConfig
	// Outbound config
	var outBoundConfig []*core.OutboundHandlerConfig
	sendthrough := "origin"
	settings := `{"domainStrategy": "UseIPv4v6"}`
	rawsettings := json.RawMessage(settings)
	default_outbound := &coreConf.OutboundDetourConfig{
		Protocol:    "freedom",
		SendThrough: &sendthrough,
		Tag:         "Default_Outbound",
		Settings:    &rawsettings,
	}
	ob, err := default_outbound.Build()
	if err != nil {
		log.WithField("err", err).Panic("Failed to understand Outbound config. Please check: https://xtls.github.io/config/outbound.html for help")
	}
	outBoundConfig = append(outBoundConfig, ob)

	// Policy config
	levelPolicyConfig := &coreConf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         proto.Uint32(4),
		ConnectionIdle:    proto.Uint32(30),
		UplinkOnly:        proto.Uint32(2),
		DownlinkOnly:      proto.Uint32(4),
		BufferSize:        proto.Int32(64),
	}
	corePolicyConfig := &coreConf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*coreConf.Policy{0: levelPolicyConfig}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Xray conf
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}
	server, err := core.New(config)
	if err != nil {
		log.WithField("err", err).Panic("failed to create instance")
	}
	log.Info("Xray Core Version: ", core.Version())
	return server
}
