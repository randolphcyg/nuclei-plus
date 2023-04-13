package nucleiplus

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
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
)

func Nuclei(outputWriter *testutils.MockOutputWriter, target string, templatePaths []string, debug bool, excludeTags goflags.StringSlice) (err error) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	defaultOpts := types.DefaultOptions()

	protocolstate.Init(defaultOpts)
	protocolinit.Init(defaultOpts)

	defaultOpts.Validate = true
	defaultOpts.UpdateTemplates = true
	defaultOpts.Debug = debug
	defaultOpts.Verbose = true
	defaultOpts.EnableProgressBar = true
	defaultOpts.ExcludeTags = excludeTags
	defaultOpts.Templates = templatePaths

	home, _ := os.UserHomeDir()
	templatesDirectory := path.Join(home, TemplatesDirectory)

	err = ValidateTemplatePaths(templatesDirectory, templatePaths, defaultOpts.Workflows)
	if err != nil {
		return err
	}

	catalog := disk.NewCatalog(templatesDirectory)

	interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		err = errors.Wrap(err, "Could not create interact client")
		return
	}
	defer interactClient.Close()

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
		err = errors.Wrap(err, "Could not create workflow loader")
		return
	}
	executerOpts.WorkflowLoader = workflowLoader

	configObject, err := config.ReadConfiguration()
	if err != nil {
		err = errors.Wrap(err, "Could not read config")
		return
	}
	store, err := loader.New(loader.NewConfig(defaultOpts, configObject, catalog, executerOpts))
	if err != nil {
		err = errors.Wrap(err, "Could not create loader client")
		return
	}
	store.Load()

	targets := []*contextargs.MetaInput{{Input: target}}
	input := &inputs.SimpleInputProvider{Inputs: targets}
	_ = engine.Execute(store.Templates(), input)
	engine.WorkPool().Wait() // Wait for the scan to finish

	return
}

func ValidateTemplatePaths(templatesDirectory string, templatePaths, workflowPaths []string) (err error) {
	allGivenTemplatePaths := append(templatePaths, workflowPaths...)
	for _, templatePath := range allGivenTemplatePaths {
		if templatesDirectory != templatePath && filepath.IsAbs(templatePath) {
			fileInfo, err := os.Stat(templatePath)
			if err == nil && fileInfo.IsDir() {
				relativizedPath, err := filepath.Rel(templatesDirectory, templatePath)
				if err != nil || (len(relativizedPath) >= 2 && relativizedPath[:2] == "..") {
					gologger.Warning().Msgf("The given path (%s) is outside the default template directory path (%s)! "+
						"Referenced sub-templates with relative paths in workflows will be resolved against the default template directory.", templatePath, templatesDirectory)
					return err
				}
			}
		}

		// verify template
		for _, p := range templatePaths {
			_, err = parsers.LoadTemplate(p, &filter.TagFilter{}, nil, disk.NewCatalog(templatesDirectory))
			if err != nil {
				return errors.Wrap(err, p)
			}
		}

	}

	return
}
