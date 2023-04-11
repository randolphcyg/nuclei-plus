package nucleiplus

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/github"
	jsoniter "github.com/json-iterator/go"
	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei-updatecheck-api/client"
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

func Nuclei(target string, templatePath string, outputWriter *testutils.MockOutputWriter) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	//配置选项
	defaultOpts := types.DefaultOptions()

	protocolstate.Init(defaultOpts)
	protocolinit.Init(defaultOpts)

	defaultOpts.Validate = true
	defaultOpts.UpdateTemplates = true
	defaultOpts.Debug = true
	defaultOpts.Verbose = true
	defaultOpts.EnableProgressBar = true

	if len(templatePath) == 0 {
		home, _ := os.UserHomeDir()
		templatePath = path.Join(home, "nuclei-templates")
	}

	defaultOpts.Templates = goflags.StringSlice{
		templatePath,
	}

	// 排除的标记列表 这里不使用.nuclei-ignore文件来排除，直接在这里指定
	defaultOpts.ExcludeTags = goflags.StringSlice{"dos", "misc"}

	interactOpts := interactsh.NewDefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		err = errors.Wrap(err, "Could not create interact client")
		log.Error(err)
	}
	defer interactClient.Close()

	catalog := disk.NewCatalog(templatePath)
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
		log.Error(err)
	}
	executerOpts.WorkflowLoader = workflowLoader

	configObject, err := config.ReadConfiguration()
	if err != nil {
		err = errors.Wrap(err, "Could not read config")
		log.Error(err)
	}
	store, err := loader.New(loader.NewConfig(defaultOpts, configObject, catalog, executerOpts))
	if err != nil {
		err = errors.Wrap(err, "Could not create loader client")
		log.Error(err)
	}
	store.Load()

	targets := []*contextargs.MetaInput{{Input: target}}
	input := &inputs.SimpleInputProvider{Inputs: targets}
	_ = engine.Execute(store.Templates(), input)
	engine.WorkPool().Wait() // Wait for the scan to finish
}

const (
	userName             = "projectdiscovery"
	repoName             = "nuclei-templates"
	nucleiIgnoreFile     = ".nuclei-ignore"
	nucleiConfigFilename = ".templates-config.json"
)

// Config contains the internal nuclei engine configuration
type Config struct {
	TemplatesDirectory string `json:"nuclei-templates-directory,omitempty"`
	TemplateVersion    string `json:"nuclei-templates-version,omitempty"`
	NucleiVersion      string `json:"nuclei-version,omitempty"`
	NucleiIgnoreHash   string `json:"nuclei-ignore-hash,omitempty"`

	NucleiLatestVersion          string `json:"nuclei-latest-version"`
	NucleiTemplatesLatestVersion string `json:"nuclei-templates-latest-version"`
}

// Exists 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func getConfigDetails() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "could not get home directory")
	}
	configDir := filepath.Join(homeDir, ".config", "nuclei")
	_ = os.MkdirAll(configDir, os.ModePerm)
	templatesConfigFile := filepath.Join(configDir, nucleiConfigFilename)
	return templatesConfigFile, nil
}

// WriteConfiguration writes the updated nuclei configuration to disk
func WriteConfiguration(config *Config) error {
	templatesConfigFile, err := getConfigDetails()
	if err != nil {
		return err
	}
	file, err := os.OpenFile(templatesConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer file.Close()

	err = jsoniter.NewEncoder(file).Encode(config)
	if err != nil {
		return err
	}
	return nil
}

type templateUpdateResults struct {
	additions     []string
	deletions     []string
	modifications []string
	totalCount    int
	checksums     map[string]string
}

// getLatestReleaseFromGithub returns the latest release from GitHub
func getLatestReleaseFromGithub(latestTag string) (*github.RepositoryRelease, error) {
	gitHubClient := github.NewClient(nil)
	release, _, err := gitHubClient.Repositories.GetReleaseByTag(context.Background(), userName, repoName, "v"+latestTag)

	if err != nil {
		return nil, err
	}
	if release == nil {
		return nil, errors.New("no version found for the templates")
	}
	return release, nil
}

// writeTemplatesChecksum writes the nuclei-templates checksum data to disk.
func writeTemplatesChecksum(file string, checksum map[string]string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	builder := &strings.Builder{}
	for k, v := range checksum {
		builder.WriteString(k)
		builder.WriteString(",")
		builder.WriteString(v)
		builder.WriteString("\n")

		if _, checksumErr := f.WriteString(builder.String()); checksumErr != nil {
			return err
		}
		builder.Reset()
	}
	return nil
}

// downloadReleaseAndUnzip downloads and unzips the release in a directory
func downloadReleaseAndUnzip(ctx context.Context, downloadURL string, templatesDirectory string) (*templateUpdateResults, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request to %s: %s", downloadURL, err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download a release file from %s: %s", downloadURL, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download a release file from %s: Not successful status %d", downloadURL, res.StatusCode)
	}

	buf, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create buffer for zip file: %s", err)
	}

	reader := bytes.NewReader(buf)
	zipReader, err := zip.NewReader(reader, reader.Size())
	if err != nil {
		return nil, fmt.Errorf("failed to uncompress zip file: %s", err)
	}

	// Create the template folder if it doesn't exist
	if err := os.MkdirAll(templatesDirectory, os.ModePerm); err != nil {
		return nil, fmt.Errorf("failed to create template base folder: %s", err)
	}

	results, err := compareAndWriteTemplates(zipReader, templatesDirectory)
	if err != nil {
		return nil, fmt.Errorf("failed to write templates: %s", err)
	}

	checksumFile := filepath.Join(templatesDirectory, ".checksum")
	if err := writeTemplatesChecksum(checksumFile, results.checksums); err != nil {
		return nil, errors.Wrap(err, "could not write checksum")
	}

	// Write the additions to a cached file for new runs.
	additionsFile := filepath.Join(templatesDirectory, ".new-additions")
	buffer := &bytes.Buffer{}
	for _, addition := range results.additions {
		buffer.WriteString(addition)
		buffer.WriteString("\n")
	}

	if err := os.WriteFile(additionsFile, buffer.Bytes(), os.ModePerm); err != nil {
		return nil, errors.Wrap(err, "could not write new additions file")
	}
	return results, err
}

// compareAndWriteTemplates compares and returns the stats of a template update operations.
func compareAndWriteTemplates(zipReader *zip.Reader, templatesDirectory string) (*templateUpdateResults, error) {
	results := &templateUpdateResults{
		checksums: make(map[string]string),
	}

	// We use file-checksums that are md5 hashes to store the list of files->hashes
	// that have been downloaded previously.
	// If the path isn't found in new update after being read from the previous checksum,
	// it is removed. This allows us fine-grained control over the download process
	// as well as solves a long problem with nuclei-template updates.
	checksumFile := filepath.Join(templatesDirectory, ".checksum")
	templateChecksumsMap, _ := createTemplateChecksumsMap(checksumFile)
	for _, zipTemplateFile := range zipReader.File {
		directory, name := filepath.Split(zipTemplateFile.Name)
		if name == "" {
			continue
		}
		paths := strings.Split(directory, string(os.PathSeparator))
		finalPath := filepath.Join(paths[1:]...)

		if strings.HasPrefix(name, ".") || strings.HasPrefix(finalPath, ".") || strings.EqualFold(name, "README.md") {
			continue
		}
		results.totalCount++
		templateDirectory := filepath.Join(templatesDirectory, finalPath)
		if err := os.MkdirAll(templateDirectory, os.ModePerm); err != nil {
			return nil, fmt.Errorf("failed to create template folder %s : %s", templateDirectory, err)
		}

		templatePath := filepath.Join(templateDirectory, name)

		isAddition := false
		if _, statErr := os.Stat(templatePath); os.IsNotExist(statErr) {
			isAddition = true
		}
		templateFile, err := os.OpenFile(templatePath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0777)
		if err != nil {
			templateFile.Close()
			return nil, fmt.Errorf("could not create uncompressed file: %s", err)
		}

		zipTemplateFileReader, err := zipTemplateFile.Open()
		if err != nil {
			templateFile.Close()
			return nil, fmt.Errorf("could not open archive to extract file: %s", err)
		}
		hasher := md5.New()

		// Save file and also read into hasher for md5
		if _, err := io.Copy(templateFile, io.TeeReader(zipTemplateFileReader, hasher)); err != nil {
			templateFile.Close()
			return nil, fmt.Errorf("could not write template file: %s", err)
		}
		templateFile.Close()

		oldChecksum, checksumOK := templateChecksumsMap[templatePath]

		checksum := hex.EncodeToString(hasher.Sum(nil))
		if isAddition {
			results.additions = append(results.additions, filepath.Join(finalPath, name))
		} else if checksumOK && oldChecksum[0] != checksum {
			results.modifications = append(results.modifications, filepath.Join(finalPath, name))
		}
		results.checksums[templatePath] = checksum
	}

	// If we don't find the previous file in the newly downloaded list,
	// and it hasn't been changed on the disk, delete it.
	for templatePath, templateChecksums := range templateChecksumsMap {
		_, ok := results.checksums[templatePath]
		if !ok && templateChecksums[0] == templateChecksums[1] {
			_ = os.Remove(templatePath)
			results.deletions = append(results.deletions, strings.TrimPrefix(strings.TrimPrefix(templatePath, templatesDirectory), string(os.PathSeparator)))
		}
	}
	return results, nil
}

// createTemplateChecksumsMap reads the previous checksum file from the disk.
// Creates a map of template paths and their previous and currently calculated checksums as values.
func createTemplateChecksumsMap(checksumsFilePath string) (map[string][2]string, error) {
	checksumFile, err := os.Open(checksumsFilePath)
	if err != nil {
		return nil, err
	}
	defer checksumFile.Close()
	scanner := bufio.NewScanner(checksumFile)

	templatePathChecksumsMap := make(map[string][2]string)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}

		parts := strings.Split(text, ",")
		if len(parts) < 2 {
			continue
		}
		templatePath := parts[0]
		expectedTemplateChecksum := parts[1]

		templateFile, err := os.Open(templatePath)
		if err != nil {
			return nil, err
		}

		hasher := md5.New()
		if _, err := io.Copy(hasher, templateFile); err != nil {
			return nil, err
		}
		templateFile.Close()

		values := [2]string{expectedTemplateChecksum}
		values[1] = hex.EncodeToString(hasher.Sum(nil))
		templatePathChecksumsMap[templatePath] = values
	}
	return templatePathChecksumsMap, nil
}

func Setup() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Error(err)
	}
	// 创建配置文件夹
	configDir := filepath.Join(home, ".config", "nuclei")

	if !Exists(configDir) {
		_ = os.MkdirAll(configDir, os.ModePerm)
		fmt.Println("Create ", configDir)
	}

	// 下载 poc 文件
	versions, err := client.GetLatestNucleiTemplatesVersion()
	if err != nil {
		log.Error(err)
		return
	}

	currentConfig := &Config{
		TemplatesDirectory:           filepath.Join(home, "nuclei-templates"),
		NucleiVersion:                config.Version,
		TemplateVersion:              "9.4.1",
		NucleiIgnoreHash:             versions.IgnoreHash,
		NucleiTemplatesLatestVersion: versions.Templates,
		NucleiLatestVersion:          versions.Nuclei,
	}
	// 创建 .templates-config.json
	if writeErr := WriteConfiguration(currentConfig); writeErr != nil {
		err = errors.Wrap(writeErr, "could not read configuration file")
		log.Error(err)
	}

	templatesDirectory := filepath.Join(home, "nuclei-templates")

	ctx := context.Background()

	if err != nil {
		gologger.Warning().Msgf("Could not fetch latest releases: %s", err)
	}
	if !Exists(templatesDirectory) {
		fmt.Println("nuclei-templates are not installed, installing...")
		asset, getErr := getLatestReleaseFromGithub(versions.Templates)
		if getErr != nil {
			err = errors.Wrap(getErr, "occur error when get latest release of templates")
			log.Error(err)
		}
		gologger.Verbose().Msgf("Downloading nuclei-templates (v%s) to %s\n", config.Version, templatesDirectory)

		if _, err := downloadReleaseAndUnzip(ctx, asset.GetZipballURL(), templatesDirectory); err != nil {
			err = errors.Wrap(err, "occur error when download templates")
			log.Error(err)
		}
	}

	fmt.Println("nuclei templates is ready: ", templatesDirectory)

}
