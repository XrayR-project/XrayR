package cmd

import (
	"net"
	"strings"
	"time"

	"github.com/XrayR-project/XrayR/common/legocmd/log"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/providers/http/memcached"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/urfave/cli"
)

func setupChallenges(ctx *cli.Context, client *lego.Client) {
	if !ctx.GlobalBool("http") && !ctx.GlobalBool("tls") && !ctx.GlobalIsSet("dns") {
		log.Panic("No challenge selected. You must specify at least one challenge: `--http`, `--tls`, `--dns`.")
	}

	if ctx.GlobalBool("http") {
		err := client.Challenge.SetHTTP01Provider(setupHTTPProvider(ctx))
		if err != nil {
			log.Panic(err)
		}
	}

	if ctx.GlobalBool("tls") {
		err := client.Challenge.SetTLSALPN01Provider(setupTLSProvider(ctx))
		if err != nil {
			log.Panic(err)
		}
	}

	if ctx.GlobalIsSet("dns") {
		setupDNS(ctx, client)
	}
}

func setupHTTPProvider(ctx *cli.Context) challenge.Provider {
	switch {
	case ctx.GlobalIsSet("http.webroot"):
		ps, err := webroot.NewHTTPProvider(ctx.GlobalString("http.webroot"))
		if err != nil {
			log.Panic(err)
		}
		return ps
	case ctx.GlobalIsSet("http.memcached-host"):
		ps, err := memcached.NewMemcachedProvider(ctx.GlobalStringSlice("http.memcached-host"))
		if err != nil {
			log.Panic(err)
		}
		return ps
	case ctx.GlobalIsSet("http.port"):
		iface := ctx.GlobalString("http.port")
		if !strings.Contains(iface, ":") {
			log.Panicf("The --http switch only accepts interface:port or :port for its argument.")
		}

		host, port, err := net.SplitHostPort(iface)
		if err != nil {
			log.Panic(err)
		}

		srv := http01.NewProviderServer(host, port)
		if header := ctx.GlobalString("http.proxy-header"); header != "" {
			srv.SetProxyHeader(header)
		}
		return srv
	case ctx.GlobalBool("http"):
		srv := http01.NewProviderServer("", "")
		if header := ctx.GlobalString("http.proxy-header"); header != "" {
			srv.SetProxyHeader(header)
		}
		return srv
	default:
		log.Panic("Invalid HTTP challenge options.")
		return nil
	}
}

func setupTLSProvider(ctx *cli.Context) challenge.Provider {
	switch {
	case ctx.GlobalIsSet("tls.port"):
		iface := ctx.GlobalString("tls.port")
		if !strings.Contains(iface, ":") {
			log.Panicf("The --tls switch only accepts interface:port or :port for its argument.")
		}

		host, port, err := net.SplitHostPort(iface)
		if err != nil {
			log.Panic(err)
		}

		return tlsalpn01.NewProviderServer(host, port)
	case ctx.GlobalBool("tls"):
		return tlsalpn01.NewProviderServer("", "")
	default:
		log.Panic("Invalid HTTP challenge options.")
		return nil
	}
}

func setupDNS(ctx *cli.Context, client *lego.Client) {
	provider, err := dns.NewDNSChallengeProviderByName(ctx.GlobalString("dns"))
	if err != nil {
		log.Panic(err)
	}

	servers := ctx.GlobalStringSlice("dns.resolvers")
	err = client.Challenge.SetDNS01Provider(provider,
		dns01.CondOption(len(servers) > 0,
			dns01.AddRecursiveNameservers(dns01.ParseNameservers(ctx.GlobalStringSlice("dns.resolvers")))),
		dns01.CondOption(ctx.GlobalBool("dns.disable-cp"),
			dns01.DisableCompletePropagationRequirement()),
		dns01.CondOption(ctx.GlobalIsSet("dns-timeout"),
			dns01.AddDNSTimeout(time.Duration(ctx.GlobalInt("dns-timeout"))*time.Second)),
	)
	if err != nil {
		log.Panic(err)
	}
}
