package main

import (
	"github.com/alecthomas/kong"

	"github.com/Cloud-Foundations/Dominator/lib/log/cmdlogger"
	"github.com/Cloud-Foundations/golib/pkg/log"
)

// begin kong migration
type Globals struct {
	Debug     bool            `short:"D" help:"Enable debug mode"`
	SecretARN string          `help:"location of secret to use"`
	AwsRegion string          `help:"AWS region for secret"`
	Logger    log.DebugLogger `kong:"-"`
}

type CLI struct {
	Globals

	Generate    GenerateCmd    `cmd:"" help:"Attach local standard input, output, and error streams to a running container"`
	PrintPublic PrintPublicCmd `cmd:"" help:"PrintPublicKey from AWS data"`
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
		kong.Description("A self-sufficient runtime for containers"),
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
