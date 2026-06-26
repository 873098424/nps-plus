//go:build !sdk

package main

import (
	"context"
	goflag "flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/djylb/nps/client"
	"github.com/djylb/nps/lib/logs"
	"github.com/djylb/nps/lib/version"
	flag "github.com/spf13/pflag"
)

// Config
var (
	ver              = flag.BoolP("version", "v", false, "Show current version")
	serverAddr       = flag.StringP("server", "s", "", "Server addr (ip1:port1,ip2:port2)")
	verifyKey        = flag.StringP("vkey", "k", "", "Authentication key (eg: vkey1,vkey2)")
	connType         = flag.StringP("type", "t", "tcp", "Connection type with the server (tcp|tls|kcp|quic|ws|wss) (eg: tcp,tls)")
	configPath       = flag.StringP("config", "c", "", "Configuration file path (path1,path2)")
	launchPayloads   = flag.StringArray("launch", nil, "Quick launch payload (repeatable; supports npc://, URL, base64, JSON)")
	proxyUrl         = flag.String("proxy", "", "Proxy socks5 URL (eg: socks5://user:pass@127.0.0.1:9007)")
	localIP          = flag.String("local_ip", "", "Local source IP for outbound connections")
	localIPForward   = flag.Bool("local_ip_forward", false, "Apply local_ip to tunnel forwarding egress for public IP/domain targets")
	localType        = flag.String("local_type", "p2p", "P2P target type")
	localPort        = flag.Int("local_port", 2000, "P2P local port")
	password         = flag.String("password", "", "P2P password flag")
	target           = flag.String("target", "", "P2P target")
	targetType       = flag.String("target_type", "all", "P2P target connection type (all|tcp|udp)")
	p2pType          = flag.String("p2p_type", "quic", "P2P connection type (quic|kcp)")
	localProxy       = flag.Bool("local_proxy", false, "Secret enable proxy local (true or false)")
	fallbackSecret   = flag.Bool("fallback_secret", true, "P2P fallback secret (true or false)")
	disableP2P       = flag.Bool("disable_p2p", false, "Disable P2P connection (true or false)")
	registerTime     = flag.Int("time", 2, "Register time in hours")
	logType          = flag.String("log", "file", "Log output mode (stdout|file|both|off)")
	logLevel         = flag.String("log_level", "trace", "Log level (trace|debug|info|warn|error|fatal|panic|off)")
	logPath          = flag.String("log_path", "", "NPC log path (empty to use default, 'off' to disable)")
	logMaxSize       = flag.Int("log_max_size", 5, "Maximum log file size in MB before rotation (0 to disable)")
	logMaxDays       = flag.Int("log_max_days", 7, "Number of days to retain old log files (0 to disable)")
	logMaxFiles      = flag.Int("log_max_files", 10, "Maximum number of log files to retain (0 to disable)")
	logCompress      = flag.Bool("log_compress", false, "Compress rotated log files (true or false)")
	logColor         = flag.Bool("log_color", true, "Enable ANSI color codes in console output (true or false)")
	debug            = flag.Bool("debug", true, "Enable debug mode")
	pprofAddr        = flag.String("pprof", "", "PProf debug address (ip:port)")
	protoVer         = flag.Int("proto_version", version.GetLatestIndex(), fmt.Sprintf("Protocol version (0-%d)", version.GetLatestIndex()))
	skipVerify       = flag.Bool("skip_verify", false, "Skip application-level server certificate fingerprint verification")
	disconnectTime   = flag.Int("disconnect_timeout", 30, "Disconnect timeout in seconds")
	keepAlive        = flag.Int("keepalive", 0, "KeepAlive Period in seconds")
	p2pTime          = flag.Int("p2p_timeout", 5, "P2P timeout in seconds")
	dnsServer        = flag.String("dns_server", "8.8.8.8", "DNS server for domain lookup")
	ntpServer        = flag.String("ntp_server", "", "NTP server for time synchronization")
	ntpInterval      = flag.Int("ntp_interval", 5, "interval between NTP synchronizations (minutes)")
	tlsEnable        = flag.Bool("tls_enable", false, "Enable TLS (Deprecated)")
	timezone         = flag.String("timezone", "", "Time zone to use for time(eg: Asia/Shanghai)")
	genTOTP          = flag.Bool("gen2fa", false, "Generate TOTP Secret")
	getTOTP          = flag.String("get2fa", "", "Get TOTP Code")
	autoReconnect    = flag.Bool("auto_reconnect", true, "Auto Reconnect")
	resolvedLaunch   *client.LaunchSpec
	launchResolveErr error
)

const (
	defaultLaunchSourceRetryDelay = 30 * time.Second
	defaultLaunchSourcePauseDelay = 5 * time.Minute
	defaultLaunchReconnectDelay   = 5 * time.Second
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
	if handleImmediateFlags() {
		return
	}
	if handleLightweightNPCCommand(cmd) {
		return
	}
	prepareNPCStartup(cmd)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prg := NewNpc(ctx)
	go waitForShutdownSignals(func() {
		prg.signalExit()
		cancel()
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

func handleLightweightNPCCommand(cmd string) bool {
	switch cmd {
	case "":
		return false
	case "status":
		server, vkey, tp, proxy, ip, err := launchCommandArgs()
		if err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
		statuses, err := client.GetTaskStatus(server, vkey, tp, proxy, ip)
		if err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
		fmt.Print(client.FormatTaskStatus(statuses))
		return true
	case "register":
		server, vkey, tp, proxy, ip, err := launchCommandArgs()
		if err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
		if err := client.RegisterLocalIp(server, vkey, tp, proxy, ip, *registerTime); err != nil {
			logs.Error("%v", err)
			os.Exit(1)
		}
		logs.Info("Successful ip registration for local public network, the validity period is %d hours.", *registerTime)
		return true
	case "install", "start", "stop", "restart", "uninstall", "update":
		logs.Warn("command %q is not available in lightweight mode", cmd)
		return true
	default:
		return false
	}
}
