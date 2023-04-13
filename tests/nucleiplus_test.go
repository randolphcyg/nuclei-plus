package tests

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"

	nucleiplus "nuclei-plus"
)

func TestNuclei(t *testing.T) {
	// download config & templates
	nucleiplus.Setup()

	// targets
	targets := []string{
		"http://192.168.126.128:8080",
	}

	// template
	//templatePaths := []string{"/root/nuclei-templates/cves/2021/CVE-2021-3129.yaml"}
	templatePaths := []string{"CVE-2021-3129.yaml"}
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
			fmt.Println(err)
		}
	}

	// result
	for _, info := range results {
		fmt.Println(info)
	}
}
