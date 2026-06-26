package main

import (
	goflag "flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/djylb/nps/bridge"
	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
	"github.com/djylb/nps/lib/daemon"
	"github.com/djylb/nps/lib/file"
	"github.com/djylb/nps/lib/install"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/policy"
	"github.com/djylb/nps/lib/servercfg"
	"github.com/djylb/nps/lib/serverreload"
	"github.com/djylb/nps/lib/version"
	"github.com/djylb/nps/server"
	"github.com/djylb/nps/server/connection"
	"github.com/djylb/nps/web/routers"
	"github.com/gin-gonic/gin"
	"github.com/kardianos/service"
	flag "github.com/spf13/pflag"
)

var (
	logLevel string
	confPath = flag.StringP("conf_path", "c", "", "Set Conf Path")
	ver      = flag.BoolP("version", "v", false, "Show Current Version")
	genTOTP  = flag.Bool("gen2fa", false, "Generate TOTP Secret")
	getTOTP  = flag.String("get2fa", "", "Get TOTP Code")
)

func main() {
	flag.CommandLine.SetNormalizeFunc(func(f *flag.FlagSet, name string) flag.NormalizedName {
		name = strings.ReplaceAll(name, "-", "_")
		name = strings.ReplaceAll(name, ".", "_")
		return flag.NormalizedName(name)
	})
	normalizeLegacyLongFlags()
	flag.CommandLine.SortFlags = false
	flag.CommandLine.SetInterspersed(true)
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)
	flag.Parse()

	cmd := parsePrimaryCommand(flag.Args())
	if cmd != "" {
		logs.Warn("command %q is ignored in lightweight mode", cmd)
	}
	if handleImmediateFlags() {
		return
	}
	startup, err := loadStartupConfig(*confPath)
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	logSettings := startup.LogSettings
	logLevel = logSettings.Level
	logs.Init(logSettings.Type, logLevel, logSettings.Path, logSettings.MaxSize, logSettings.MaxFiles, logSettings.MaxDays, logSettings.Compress, logSettings.Color)
	prg := &nps{}
	go waitForShutdownSignals(func() {
		routers.StopManagedRuntime()
		prg.signalExit()
	})
	_ = prg.run()
}

func normalizeLegacyLongFlags() {
	norm := func(s string) string {
		s = strings.ReplaceAll(s, "-", "_")
		s = strings.ReplaceAll(s, ".", "_")
		return s
	}
	defined := map[string]struct{}{}
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		defined[norm(f.Name)] = struct{}{}
	})
	if len(os.Args) <= 1 {
		return
	}
	out := make([]string, 0, len(os.Args))
	out = append(out, os.Args[0])
	for _, a := range os.Args[1:] {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && len(a) > 2 {
			s := a[1:]
			name, val := s, ""
			if i := strings.IndexByte(s, '='); i >= 0 {
				name, val = s[:i], s[i:]
			}
			if _, ok := defined[norm(name)]; ok {
				a = "--" + name + val
			}
		}
		out = append(out, a)
	}
	os.Args = out
}

type nps struct {
	exit     chan struct{}
	exitInit sync.Once
	exitStop sync.Once
}

func (p *nps) Start(s service.Service) error {
	_, _ = s.Status()
	p.exitChan()
	go func() { _ = p.run() }()
	return nil
}
func (p *nps) Stop(s service.Service) error {
	_, _ = s.Status()
	routers.StopManagedRuntime()
	p.signalExit()
	if npsServiceInteractive() {
		os.Exit(0)
	}
	return nil
}

func (p *nps) run() error {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			logs.Warn("nps: panic serving %v: %s", err, buf)
		}
	}()
	run()
	<-p.exitChan()
	logs.Warn("stop...")
	return nil
}

var npsServiceInteractive = service.Interactive

func (p *nps) exitChan() chan struct{} {
	if p == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	p.exitInit.Do(func() {
		if p.exit == nil {
			p.exit = make(chan struct{})
		}
	})
	return p.exit
}

func (p *nps) signalExit() {
	if p == nil {
		return
	}
	ch := p.exitChan()
	p.exitStop.Do(func() {
		close(ch)
	})
}

func waitForShutdownSignals(stop func()) {
	if stop == nil {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(ch)
	<-ch
	stop()
}

type npsStartup struct {
	Config      *servercfg.Snapshot
	LogSettings serverreload.LogSettings
}

func parsePrimaryCommand(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func handleImmediateFlags() bool {
	if *genTOTP {
		crypt.PrintTOTPSecret()
		return true
	}
	if *getTOTP != "" {
		crypt.PrintTOTPCode(*getTOTP)
		return true
	}
	if *ver {
		version.PrintVersion(version.GetLatestIndex())
		return true
	}
	return false
}

func loadStartupConfig(path string) (npsStartup, error) {
	applyConfiguredPathFlag(path)
	if err := servercfg.LoadDefault(); err != nil {
		return npsStartup{}, fmt.Errorf("load config file error: %w", err)
	}
	cfg := servercfg.Current()
	policy.SetDefaultGeoIPPath(policy.ResolveGeoIPPath(servercfg.Path(), cfg.App.GeoIPPath))
	policy.SetDefaultGeoSitePath(policy.ResolveGeoSitePath(servercfg.Path(), cfg.App.GeoSitePath))
	if strings.TrimSpace(os.Getenv("GIN_MODE")) == "" {
		gin.SetMode(gin.ReleaseMode)
	}
	if cfg.App.PprofPort != "0" {
		common.InitPProfByAddr(common.BuildAddress(cfg.App.PprofIP, cfg.App.PprofPort))
	}
	if tz := strings.TrimSpace(cfg.App.Timezone); tz != "" {
		if err := common.SetTimezone(tz); err != nil {
			logs.Warn("Set timezone error %v", err)
		}
	}
	common.SetCustomDNS(cfg.App.DNSServer)
	return npsStartup{
		Config:      cfg,
		LogSettings: serverreload.ResolveLogSettings(cfg),
	}, nil
}

func applyConfiguredPathFlag(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if servercfg.IsSupportedConfigPath(path) {
		servercfg.SetPreferredPath(path)
		common.ConfPath = filepath.Dir(path)
		return
	}
	common.ConfPath = path
}

func buildNPSServiceConfig(args []string) *service.Config {
	options := make(service.KeyValue)
	svcConfig := &service.Config{
		Name:        "Nps",
		DisplayName: "nps内网穿透代理服务器",
		Description: "一款轻量级、功能强大的内网穿透代理服务器。支持tcp、udp流量转发，支持内网http代理、内网socks5代理，同时支持snappy压缩、站点保护、加密传输、多路复用、header修改等。支持web图形化管理，集成多用户模式。",
		Option:      options,
	}
	for _, arg := range args {
		switch arg {
		case "install", "start", "stop", "uninstall", "restart":
			continue
		}
		svcConfig.Arguments = append(svcConfig.Arguments, arg)
	}
	svcConfig.Arguments = append(svcConfig.Arguments, "service")
	if !common.IsWindows() {
		svcConfig.Dependencies = []string{
			"Requires=network.target",
			"After=network-online.target syslog.target",
		}
		svcConfig.Option["SystemdScript"] = install.SystemdScript
		svcConfig.Option["SysvScript"] = install.SysvScript
	}
	return svcConfig
}

func handleNPSServiceCommand(cmd string, svc service.Service, svcConfig *service.Config, prg *nps) bool {
	if cmd == "" || cmd == "service" {
		return false
	}
	switch cmd {
	case "reload":
		daemon.InitDaemon("nps", common.GetRunPath(), common.GetTmpPath())
		return true
	case "install":
		_ = service.Control(svc, "stop")
		_ = service.Control(svc, "uninstall")

		executable, err := install.NPS()
		if err != nil {
			logs.Error("%v", err)
			return true
		}
		svcConfig.Executable = executable
		installedSvc, err := service.New(prg, svcConfig)
		if err != nil {
			logs.Error("%v", err)
			return true
		}
		if err := service.Control(installedSvc, cmd); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			confPath := "/etc/init.d/" + svcConfig.Name
			_ = os.Symlink(confPath, "/etc/rc.d/S90"+svcConfig.Name)
			_ = os.Symlink(confPath, "/etc/rc.d/K02"+svcConfig.Name)
		}
		return true
	case "start", "restart", "stop":
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			command := exec.Command("/etc/init.d/"+svcConfig.Name, cmd)
			if err := command.Run(); err != nil {
				logs.Error("%v", err)
			}
			return true
		}
		if err := service.Control(svc, cmd); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		return true
	case "uninstall":
		if err := service.Control(svc, cmd); err != nil {
			logs.Error("Valid actions: %q error: %v", service.ControlAction, err)
		}
		if service.Platform() == "unix-systemv" {
			logs.Info("unix-systemv service")
			_ = os.Remove("/etc/rc.d/S90" + svcConfig.Name)
			_ = os.Remove("/etc/rc.d/K02" + svcConfig.Name)
		}
		return true
	case "update":
		if err := install.UpdateNps(); err != nil {
			logs.Error("%v", err)
		}
		return true
	default:
		return false
	}
}

func run() {
	cfg := servercfg.Current()
	file.MigrateLegacyData()

	runMode := resolveServerRunMode(cfg)
	warnLegacyManagedNodeMode(cfg, runMode)
	initializeServerRuntime(cfg)
	startServerProcesses(true, cfg.Runtime.DisconnectTimeout)
}

func resolveServerRunMode(cfg *servercfg.Snapshot) string {
	runMode := strings.ToLower(strings.TrimSpace(cfg.Runtime.RunMode))
	if runMode == "" {
		return "standalone"
	}
	return runMode
}

func warnLegacyManagedNodeMode(cfg *servercfg.Snapshot, runMode string) {
	if runMode == "node" && strings.TrimSpace(cfg.Runtime.MasterURL) != "" && strings.TrimSpace(cfg.Runtime.NodeToken) != "" {
		logs.Warn("legacy remote-managed node mode is deprecated; using local store with management platform compatibility")
	}
}

func initializeServerRuntime(cfg *servercfg.Snapshot) {
	initializeServerStore()
	applyServerRuntimeConfig()
	logServerStartup()
	connection.InitConnectionService()
	applyBridgeServerToggles(cfg)
}

func initializeServerStore() {
	file.GlobalStore = file.NewLocalStore()
}

func applyServerRuntimeConfig() {
	if err := serverreload.ApplyCurrentConfig(); err != nil {
		logs.Error("apply runtime config failed: %v", err)
	}
}

func logServerStartup() {
	logs.Info("the config path is: %s", servercfg.Path())
	logs.Info("the version of server is %s, allow client core version to be %s", version.VERSION, version.GetMinVersion(bridge.ServerSecureMode))
}

func applyBridgeServerToggles(cfg *servercfg.Snapshot) {
	bridge.ServerKcpEnable = cfg.Bridge.ServerKCPEnabled
	bridge.ServerQuicEnable = cfg.Bridge.ServerQUICEnabled
	bridge.ServerTcpEnable = cfg.Bridge.ServerTCPEnabled
	bridge.ServerTlsEnable = cfg.Bridge.ServerTLSEnabled
	bridge.ServerWsEnable = cfg.Bridge.ServerWSEnabled
	bridge.ServerWssEnable = cfg.Bridge.ServerWSSEnabled
}

func startServerProcesses(enableWebServer bool, timeout int) {
	server.StartLifecycleMonitor()
	go server.StartServerEngine(enableWebServer, timeout)
}
