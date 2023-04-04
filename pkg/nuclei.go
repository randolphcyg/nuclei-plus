package helper

import (
	"context"
	"os"
	"path"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/ratelimit"
	log "github.com/sirupsen/logrus"
)

func Nuclei(target string, outputWriter *testutils.MockOutputWriter) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	//配置选项
	defaultOpts := types.DefaultOptions()

	protocolstate.Init(defaultOpts)
	protocolinit.Init(defaultOpts)

	//defaultOpts.IncludeIds = goflags.StringSlice{"cname-service"}
	//defaultOpts.ExcludeTags = config.ReadIgnoreFile().Tags

	defaultOpts.Validate = true
	defaultOpts.UpdateTemplates = true
	defaultOpts.Debug = true
	defaultOpts.Verbose = true
	defaultOpts.EnableProgressBar = true

	interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		log.Fatalf("Could not create interact client: %s\n", err)
	}
	defer interactClient.Close()

	home, _ := os.UserHomeDir()
	catalog := disk.NewCatalog(path.Join(home, "nuclei-templates"))
	executerOpts := protocols.ExecuterOptions{
		Output:          outputWriter,
		Options:         defaultOpts,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
		Interactsh:      interactClient,
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
	}
	engine := core.New(defaultOpts)
	engine.SetExecuterOptions(executerOpts)

	workflowLoader, err := parsers.NewLoader(&executerOpts)
	if err != nil {
		log.Fatalf("Could not create workflow loader: %s\n", err)
	}
	executerOpts.WorkflowLoader = workflowLoader

	configObject, err := config.ReadConfiguration()
	if err != nil {
		log.Fatalf("Could not read config: %s\n", err)
	}
	store, err := loader.New(loader.NewConfig(defaultOpts, configObject, catalog, executerOpts))
	if err != nil {
		log.Fatalf("Could not create loader client: %s\n", err)
	}
	store.Load()

	//inputArgs := []*contextargs.MetaInput{{Input: "docs.hackerone.com"}}
	targets := []*contextargs.MetaInput{{Input: target}}
	input := &inputs.SimpleInputProvider{Inputs: targets}
	_ = engine.Execute(store.Templates(), input)
	engine.WorkPool().Wait() // Wait for the scan to finish
}
