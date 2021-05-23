package main

import (
	"github.com/LeakIX/l9synscan"
	"github.com/alecthomas/kong"
	"io"
)

var App struct {
	Scan l9synscan.L9SynScanCommand `cmd help:"Scans ipv4/ipv6 from l9 input"`
	Test l9synscan.L9SynTestCommand `cmd help:"Runs on loopback to evaluate perfs"`
}

func main() {
	ctx := kong.Parse(&App)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run()
	if err != io.EOF {
		ctx.FatalIfErrorf(err)
	}
}
