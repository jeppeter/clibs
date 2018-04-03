package main

import (
	"fmt"
	"github.com/jeppeter/go-extargsparse"
	"github.com/natefinch/npipe"
	"io/ioutil"
	"os"
	"strconv"
	"time"
)

type Pipeargs struct {
	Verbose int
	Input   string
	Args    []string
}

func format_bytes(data []byte) string {
	var s = ""
	var i int
	var lasti int
	var cr rune
	var curi int

	lasti = 0
	for i = 0; i < len(data); i++ {
		if (i % 16) == 0 {
			if i > 0 {
				s += "    "
			}

			for lasti != i {
				cr = rune(data[lasti])
				if strconv.IsPrint(cr) {
					s += fmt.Sprintf("%s", string(data[lasti]))
				} else {
					s += "."
				}
				lasti++
			}

			s += "\n"
			s += fmt.Sprintf("[0x%08x]", i)
		}

		s += fmt.Sprintf(" 0x%02x", data[i])
	}

	if lasti != i {
		curi = i
		for (curi % 16) != 0 {
			s += fmt.Sprintf("     ")
			curi++
		}

		for lasti != i {
			cr = rune(data[lasti])
			if strconv.IsPrint(cr) {
				s += fmt.Sprintf("%s", string(data[lasti]))
			} else {
				s += "."
			}
			lasti++
		}

		s += "\n"
	}

	return s
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
			fmt.Fprintf(os.Stdout, "%s", format_bytes(data[:nbyte]))
			if nbyte < len(data) {
				break
			}
		}
	}
	return
}
