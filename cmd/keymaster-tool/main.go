package main

import (
	"github.com/alecthomas/kong"

	"github.com/Cloud-Foundations/Dominator/lib/log/cmdlogger"
	"github.com/Cloud-Foundations/golib/pkg/log"
)

type Globals struct {
	Debug     bool            `short:"D" help:"Enable debug mode"`
	SecretARN string          `help:"location of secret to use"`
	AwsRegion string          `help:"AWS region for secret"`
	Logger    log.DebugLogger `kong:"-"`
}

type CLI struct {
	Globals

	GenerateKey GenerateCmd    `cmd:"" help:"Genereate a new encrypted keypair to stdout"`
	PrintPublic PrintPublicCmd `cmd:"" help:"Print public key from encrypted file"`
}

func main() {
	logger := cmdlogger.New()
	cli := CLI{
		Globals: Globals{
			Logger: logger,
		},
	}
	ctx := kong.Parse(&cli,
		kong.Name("keymaster-tool"),
		kong.Description("A set of tools for keymaster secret management"),
		kong.UsageOnError(),
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{
			"version": "0.0.1",
		})
	err := ctx.Run(&cli.Globals)
	ctx.FatalIfErrorf(err)
}
