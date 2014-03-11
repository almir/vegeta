package main

import (
	"bytes"
	"flag"
	"fmt"
	vegeta "github.com/almir/vegeta/lib"
	"log"
	"net/http"
	"strings"
	"time"
	"strconv"
)

type rateList []uint64

// String is the method to format the flag's value, part of the flag.Value interface.
// The String method's output will be used in diagnostics.
func (i *rateList) String() string {
	return fmt.Sprint(*i)
}

// Set is the method to set the flag value, part of the flag.Value interface.
// Set's argument is a string to be parsed to set the flag.
// It's a comma-separated list, so we split it.
func (i *rateList) Set(value string) error {
	for _, singleRate := range strings.Split(value, ",") {
		oneRate, err := strconv.ParseUint(singleRate, 10, 64)
		if err != nil {
			return err
		}
		*i = append(*i, oneRate)
	}
	return nil
}

// attack validates the attack arguments, sets up the
// required resources, launches the attack and writes the results
func attack(rate uint64, duration time.Duration, targets *vegeta.Targets, ordering,
	output string, redirects int, timeout time.Duration, hdr http.Header, previousResults vegeta.Results) (vegeta.Results, error) {

	if rate == 0 {
		return nil, fmt.Errorf(errRatePrefix + "can't be zero")
	}

	if duration == 0 {
		return nil, fmt.Errorf(errDurationPrefix + "can't be zero")
	}

	targets.SetHeader(hdr)

	switch ordering {
	case "random":
		targets.Shuffle(time.Now().UnixNano())
	case "sequential":
		break
	default:
		return nil, fmt.Errorf(errOrderingPrefix+"`%s` is invalid", ordering)
	}

	if output != "stdout" {
		out, err := file(output, true)
		if err != nil {
			return nil, fmt.Errorf(errOutputFilePrefix+"(%s): %s", output, err)
		}
		defer out.Close()
	}

	vegeta.DefaultAttacker.SetRedirects(redirects)

	if timeout > 0 {
		vegeta.DefaultAttacker.SetTimeout(timeout)
	}

	log.Printf("Vegeta is attacking %d targets in %s order for %s with %d requests/sec...\n",
		len(*targets), ordering, duration, rate)
	results := vegeta.Attack(*targets, rate, duration)
	log.Println("Done!")

	return append(previousResults, results...), nil
}

func writeResults(results vegeta.Results, output string) error {
	out, _ := file(output, true)
	defer out.Close()

	log.Printf("Writing results to '%s'...", output)
	if err := results.Encode(out); err != nil {
		return err
	}
	return nil
}

func attackCmd(args []string) (command, error) {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	var rateFlag rateList = []uint64{}
	fs.Var(&rateFlag, "rates", "One or more comma separated requests per second")
	targetsf := fs.String("targets", "stdin", "Targets file")
	ordering := fs.String("ordering", "random", "Attack ordering [sequential, random]")
	duration := fs.Duration("duration", 10*time.Second, "Duration of the test")
	output := fs.String("output", "stdout", "Output file")
	redirects := fs.Int("redirects", 10, "Number of redirects to follow")
	timeout := fs.Duration("timeout", 0, "Requests timeout")
	hdrs := headers{Header: make(http.Header)}
	fs.Var(hdrs, "header", "Targets request header")
	fs.Parse(args)

	if len(rateFlag) == 0 {
		return nil, fmt.Errorf(errRatePrefix + "has to be specified and can't be empty")
	}

	in, err := file(*targetsf, false)
	if err != nil {
		return nil, fmt.Errorf(errTargetsFilePrefix+"(%s): %s", *targetsf, err)
	}
	defer in.Close()
	targets, err := vegeta.NewTargetsFrom(in)
	if err != nil {
		return nil, fmt.Errorf(errTargetsFilePrefix+"(%s): %s", *targetsf, err)
	}

	return func() error {
		results := make(vegeta.Results, 0)
		var err error = nil

		for _, rate := range rateFlag {
			if results, err = attack(rate, *duration, &targets, *ordering, *output, *redirects,
				*timeout, hdrs.Header, results); err != nil {
				return err
			}
		}
		if err = writeResults(results, *output); err != nil {
			return err
		}
		return nil
	}, nil
}

const (
	errRatePrefix        = "Rate(s): "
	errDurationPrefix    = "Duration: "
	errOutputFilePrefix  = "Output file: "
	errTargetsFilePrefix = "Targets file: "
	errOrderingPrefix    = "Ordering: "
	errReportingPrefix   = "Reporting: "
)

// headers is the http.Header used in each target request
// it is defined here to implement the flag.Value interface
// in order to support multiple identical flags for request header
// specification
type headers struct{ http.Header }

func (h headers) String() string {
	buf := &bytes.Buffer{}
	if err := h.Write(buf); err != nil {
		return ""
	}
	return buf.String()
}

func (h headers) Set(value string) error {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return fmt.Errorf("Header '%s' has a wrong format", value)
	}
	key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	if key == "" || val == "" {
		return fmt.Errorf("Header '%s' has a wrong format", value)
	}
	h.Add(key, val)
	return nil
}
