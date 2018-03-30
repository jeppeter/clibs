package main

import (
	"fmt"
	"github.com/jeppeter/go-extargsparse"
	"github.com/jeppeter/log4go"
	"github.com/natefinch/npipe"
	"os"
)

type Pipeargs struct {
	Verbose int
	Input   string
	Args    []string
}

func main() {
	var commandline = `{
			"input|i" : null,
			"$" : 1
		}`
	var args *Pipeargs
	var ns *extargsparse.NameSpaceEx
	var err error
	var parser *extargsparse.ExtArgsParse
	args = &Pipeargs{}
	parser, err = extargsparse.NewExtArgsParse(nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can not create args parse [%s]\n", err.Error())
		os.Exit(5)
	}

}
