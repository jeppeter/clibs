package main

import (
	"fmt"
	"github.com/jeppeter/go-extargsparse"
	"github.com/natefinch/npipe"
	"io/ioutil"
	"os"
	"time"
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
	var err error
	var parser *extargsparse.ExtArgsParse
	var conn *npipe.PipeConn
	var data []byte
	var nbyte int
	var tbyte int = 0
	args = &Pipeargs{}
	parser, err = extargsparse.NewExtArgsParse(nil, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "can not create args parse [%s]\n", err.Error())
		os.Exit(5)
	}

	err = PrepareLog(parser)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prepare log error[%s]\n", err.Error())
		os.Exit(5)
	}

	err = parser.LoadCommandLineString(commandline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load [%s] error[%s]\n", commandline, err.Error())
		os.Exit(5)
	}

	_, err = parser.ParseCommandLineEx(nil, nil, args, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse command %v error [%s]\n", os.Args[1:], err.Error())
		os.Exit(6)
	}

	conn, err = npipe.DialTimeout(args.Args[0], time.Second*3)
	if err != nil {
		Error("can not dial [%s] error[%s]", args.Args[0], err.Error())
		os.Exit(6)
	}

	defer conn.Close()
	if args.Input != "" {
		data, err = ioutil.ReadFile(args.Input)
		if err != nil {
			Error("can not read [%s] error[%s]", args.Input, err.Error())
			os.Exit(6)
			return
		}
		for {
			nbyte, err = conn.Write(data[tbyte:])
			if err != nil {
				Error("can not write [%s] error[%s]", args.Args[0], err.Error())
				os.Exit(6)
			}

			tbyte += nbyte
			if tbyte == len(data) {
				break
			}
		}
		fmt.Fprintf(os.Stdout, "write [%s] with [%s] succ\n", args.Args[0], args.Input)
	} else {
		data = make([]byte, 4096)
		for {
			nbyte, err = conn.Read(data)
			if err != nil {
				Error("read [%s] [%d] error[%s]", args.Args[0], tbyte, err.Error())
				os.Exit(6)
				return
			}

			tbyte += nbyte
			fmt.Fprintf(os.Stdout, "%s", string(data[:nbyte]))
			if nbyte < len(data) {
				break
			}
		}
	}
	return
}
