package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const releaseAPI = "https://api.github.com/repos/snnabb/Meridian/releases/latest"

var stableVersionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var comparableVersionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:[-+][0-9A-Za-z.-]+)?$`)

type selfBuildRelease struct {
	Supported bool   `json:"supported"`
	Available bool   `json:"available"`
	URL       string `json:"url"`
	Reason    string `json:"reason,omitempty"`
}

type updateRelease struct {
	SelfBuild *selfBuildRelease `json:"self_build,omitempty"`
	Current   string            `json:"current_version"`
	Latest    string            `json:"latest_version"`
	URL       string            `json:"release_url"`
	Notes     string            `json:"notes"`
	Available bool              `json:"update_available"`
	Supported bool              `json:"update_supported"`
	Reason    string            `json:"unsupported_reason,omitempty"`
}
type updateJob struct {
	State      string `json:"state"`
	Version    string `json:"version,omitempty"`
	Message    string `json:"message"`
	StartedAt  string `json:"started_at,omitempty"`
	FinishedAt string `json:"finished_at,omitempty"`
}

func versionNewer(candidate, current string) bool {
	// Release candidates are always stable tags. The installed build may carry
	// a local preview/build suffix (for example, the account-feature test
	// build), which must still be upgradeable to the next stable release.
	a, b := stableVersionPattern.FindStringSubmatch(candidate), comparableVersionPattern.FindStringSubmatch(current)
	if a == nil || b == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		av, ae := strconv.ParseUint(a[i], 10, 64)
		bv, be := strconv.ParseUint(b[i], 10, 64)
		if ae != nil || be != nil {
			return false
		}
		if av != bv {
			return av > bv
		}
	}
	return false
}
func fetchUpdateRelease(ctx context.Context, client *http.Client, endpoint, current string) (updateRelease, error) {
	result := updateRelease{Current: current}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Meridian/"+appVersion)
	resp, err := client.Do(req)
	if err != nil {
		return result, errors.New("无法连接 GitHub，请稍后重试")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("GitHub 版本检查返回 HTTP %d，请稍后重试", resp.StatusCode)
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Body       string `json:"body"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 || json.Unmarshal(data, &release) != nil || !stableVersionPattern.MatchString(release.Tag) || release.Draft || release.Prerelease {
		return result, errors.New("版本信息无效")
	}
	result.Latest = release.Tag
	result.URL = "https://github.com/snnabb/Meridian/releases/tag/" + release.Tag
	result.Notes = release.Body
	result.Available = versionNewer(release.Tag, current)
	return result, nil
}
func updaterSocketPath() string {
	if value := strings.TrimSpace(os.Getenv("MERIDIAN_UPDATER_SOCKET")); value != "" {
		return value
	}
	return ""
}
func callUpdateAgent(ctx context.Context, method string, body io.Reader) (updateJob, error) {
	if !filepath.IsAbs(updaterSocketPath()) {
		return updateJob{}, errors.New("当前安装未启用面板更新；标准 systemd 部署可运行新版 install.sh install -y 启用")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", updaterSocketPath())
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost/update", body)
	if err != nil {
		return updateJob{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return updateJob{}, errors.New("当前安装未启用面板更新；请在服务器运行新版 install.sh install -y")
	}
	defer resp.Body.Close()
	var job updateJob
	if json.NewDecoder(io.LimitReader(resp.Body, 8192)).Decode(&job) != nil {
		return job, errors.New("更新服务响应无效")
	}
	if resp.StatusCode >= 300 {
		return job, errors.New(job.Message)
	}
	return job, nil
}
func (a *App) handleSystemUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		job, err := callUpdateAgent(r.Context(), http.MethodGet, nil)
		if err != nil {
			a.jsonOK(w, map[string]any{"state": "unavailable", "message": err.Error()})
			return
		}
		a.jsonOK(w, job)
		return
	}
	if r.Method != http.MethodPost {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	var request struct {
		Version string `json:"version"`
		Channel string `json:"channel"`
	}
	if decodeJSONBody(w, r, &request) != nil {
		a.jsonErr(w, 400, "无效更新请求")
		return
	}
	if request.Channel == "self" {
		// The self-built channel always reinstalls the current fork build; there
		// is no version comparison because the tag is a moving "local-latest".
		body, _ := json.Marshal(struct {
			Channel string `json:"channel"`
		}{Channel: "self"})
		job, err := callUpdateAgent(r.Context(), http.MethodPost, strings.NewReader(string(body)))
		if err != nil {
			a.jsonErr(w, 409, err.Error())
			return
		}
		a.jsonOK(w, job)
		return
	}
	if !stableVersionPattern.MatchString(request.Version) {
		a.jsonErr(w, 400, "请选择有效的正式版本")
		return
	}
	if !versionNewer(request.Version, appVersion) {
		a.jsonErr(w, 409, "仅允许更新到更高的正式版本")
		return
	}
	body, _ := json.Marshal(request)
	job, err := callUpdateAgent(r.Context(), http.MethodPost, strings.NewReader(string(body)))
	if err != nil {
		a.jsonErr(w, 409, err.Error())
		return
	}
	a.jsonOK(w, job)
}
func (a *App) handleSystemUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	release, err := fetchUpdateRelease(ctx, &http.Client{Timeout: 10 * time.Second}, releaseAPI, appVersion)
	if err != nil {
		a.jsonErr(w, 502, err.Error())
		return
	}
	_, err = callUpdateAgent(ctx, http.MethodGet, nil)
	release.Supported = err == nil
	if err != nil {
		release.Reason = err.Error()
	}
	// The self-built channel is separate from upstream semver tags: it always
	// compares against the fork's moving "local-latest" release.
	release.SelfBuild = selfBuildInfo(ctx)
	a.jsonOK(w, release)
}

type updateAgent struct {
	mu  sync.Mutex
	job updateJob
	run func(string) error
	// runSelfBuild reinstalls the locally built binary from the fork's own
	// release channel; it is wired only by the root agent.
	runSelfBuild func(context.Context) error
	stateFile    string
}

func (a *updateAgent) persistLocked() {
	if a.stateFile == "" {
		return
	}
	data, _ := json.Marshal(a.job)
	_ = writePrivateFileAtomic(a.stateFile, data)
}
func (a *updateAgent) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path != "/update" {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet {
		a.mu.Lock()
		job := a.job
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(job)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var request struct {
		Version string `json:"version"`
		Channel string `json:"channel"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(updateJob{Message: "无效更新请求"})
		return
	}
	selfBuild := request.Channel == "self"
	if selfBuild && a.runSelfBuild == nil {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(updateJob{Message: "当前部署未启用自用版更新"})
		return
	}
	if !selfBuild && !stableVersionPattern.MatchString(request.Version) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(updateJob{Message: "无效更新版本"})
		return
	}
	a.mu.Lock()
	if a.job.State == "running" {
		a.mu.Unlock()
		w.WriteHeader(409)
		_ = json.NewEncoder(w).Encode(updateJob{Message: "更新正在进行，请等待完成"})
		return
	}
	label := request.Version
	message := "正在下载、校验并更新；服务会短暂重启"
	if selfBuild {
		label = "self"
		message = "正在下载自用版二进制、校验并替换；服务会短暂重启"
	}
	a.job = updateJob{State: "running", Version: label, StartedAt: time.Now().UTC().Format(time.RFC3339), Message: message}
	a.persistLocked()
	job := a.job
	a.mu.Unlock()
	go func() {
		var err error
		if selfBuild {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()
			err = a.runSelfBuild(ctx)
		} else {
			err = a.run(request.Version)
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.job.FinishedAt = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			a.job.State = "failed"
			a.job.Message = "更新失败，已尝试恢复原版本；请检查服务状态及 meridian-updater 日志"
		} else {
			a.job.State = "completed"
			a.job.Message = "更新完成，健康检查通过"
		}
		a.persistLocked()
	}()
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(job)
}
func runUpdateAgent(args []string) error {
	const socket = "/run/meridian-updater/control.sock"
	const installer = "/usr/local/libexec/meridian/install.sh"
	if len(args) != 4 || args[0] != "--socket" || args[2] != "--installer" || args[1] != socket || args[3] != installer {
		return errors.New("usage: meridian update-agent --socket /run/meridian-updater/control.sock --installer /usr/local/libexec/meridian/install.sh")
	}
	if os.Geteuid() != 0 {
		return errors.New("update-agent must run as root")
	}
	if info, err := os.Lstat(socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("updater socket path is not a socket")
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = os.Chmod(socket, 0660); err != nil { // #nosec G302 -- root-owned Unix socket intentionally permits the dedicated meridian service group to connect.
		return err
	}
	agent := &updateAgent{job: updateJob{State: "idle", Message: "更新服务已就绪"}, stateFile: "/var/lib/meridian-updater/status.json"}
	if data, err := os.ReadFile(agent.stateFile); err == nil {
		_ = json.Unmarshal(data, &agent.job)
		if agent.job.State == "running" {
			agent.job.State = "failed"
			agent.job.Message = "上次更新被中断，请检查当前版本与服务状态"
		}
	}
	agent.run = func(version string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		// The path comes only from the root-owned systemd unit. HTTP input never
		// controls the executable, options, repository, filesystem or shell text.
		command := exec.CommandContext(ctx, "/bin/bash", installer, "update", "--yes") // #nosec G204 -- administrator-owned fixed installer; version is passed only as validated environment data.
		command.Env = append(os.Environ(), "MERIDIAN_EXPECTED_UPDATE_VERSION="+version)
		command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
		command.WaitDelay = 90 * time.Second
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		return command.Run()
	}
	agent.runSelfBuild = func(ctx context.Context) error {
		target, err := os.Executable()
		if err != nil {
			return err
		}
		if resolved, err := filepath.EvalSymlinks(target); err == nil {
			target = resolved
		}
		return installSelfBuild(ctx, &http.Client{Timeout: 5 * time.Minute}, target, "meridian")
	}
	server := &http.Server{Handler: agent, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	return server.Serve(listener)
}
