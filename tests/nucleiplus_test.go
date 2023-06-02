package tests

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/randolphcyg/nucleiplus"
)

func TestNuclei(t *testing.T) {
	// download config & templates
	err := nucleiplus.Setup()
	if err != nil {
		panic(err)
	}

	// targets
	targets := []string{
		"http://192.168.3.209:18080",
	}

	// template
	templatePaths := []string{"CVE-2022-22963.yaml"}
	debug := false
	excludeTags := goflags.StringSlice{"dos", "misc"}

	// output
	results := make([]*output.ResultEvent, 0)
	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		if len(event.Response) > 10240 {
			event.Response = event.Response[:10240]
		}
		results = append(results, event)
	}

	for _, target := range targets {
		err := nucleiplus.Nuclei(outputWriter, target, templatePaths, debug, excludeTags)
		if err != nil {
			panic(err)
		}
	}

	// result
	if len(results) > 0 {
		fmt.Println("======EXIST====")
		for _, info := range results {
			fmt.Println("#### RESULT：")
			fmt.Println(info)
		}
	}

	fmt.Println("======END====")
}
