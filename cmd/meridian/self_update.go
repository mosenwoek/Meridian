package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Self-hosted builds come from the fork's own release channel instead of the
// upstream semver tags. The URLs are fixed constants: HTTP input never supplies
// a repository, path or filename, so a compromised panel session cannot point
// the root agent at arbitrary content.
const (
	selfBuildBinaryURL   = "https://github.com/mosenwoek/Meridian/releases/download/local-latest/meridian-linux-amd64"
	selfBuildChecksumURL = "https://github.com/mosenwoek/Meridian/releases/download/local-latest/SHA256SUMS"
	selfBuildAssetName   = "meridian-linux-amd64"
	selfBuildMaxBytes    = 128 << 20
)

// downloadSelfBuild fetches the binary and its checksum manifest into a private
// temporary directory and verifies the SHA-256 before anything is replaced.
func downloadSelfBuild(ctx context.Context, client *http.Client, dir string) (string, error) {
	fetch := func(url string, limit int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Meridian/"+appVersion)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("下载返回 HTTP %d", resp.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, errors.New("下载内容超过大小上限")
		}
		return data, nil
	}

	checksums, err := fetch(selfBuildChecksumURL, 64<<10)
	if err != nil {
		return "", fmt.Errorf("获取校验清单失败：%w", err)
	}
	expected := ""
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == selfBuildAssetName {
			expected = strings.ToLower(fields[0])
			break
		}
	}
	if len(expected) != 64 {
		return "", errors.New("校验清单中没有此二进制的有效 SHA-256")
	}

	data, err := fetch(selfBuildBinaryURL, selfBuildMaxBytes)
	if err != nil {
		return "", fmt.Errorf("下载二进制失败：%w", err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != expected {
		return "", errors.New("SHA-256 校验失败，已放弃替换")
	}

	binaryPath := filepath.Join(dir, "meridian.new")
	if err := os.WriteFile(binaryPath, data, 0o755); err != nil { // #nosec G306 -- executable must be readable by the service user after install.
		return "", err
	}
	return binaryPath, nil
}

// installSelfBuild swaps the running binary using a rename in the same
// directory, keeping a timestamped backup that is restored if the service does
// not come back healthy.
func installSelfBuild(ctx context.Context, client *http.Client, target, service string) (err error) {
	if target == "" {
		return errors.New("目标二进制路径为空")
	}
	dir := filepath.Dir(target)
	tmp, err := os.MkdirTemp(dir, ".meridian-selfupdate-")
	if err != nil {
		return fmt.Errorf("无法创建临时目录：%w", err)
	}
	defer os.RemoveAll(tmp)

	binaryPath, err := downloadSelfBuild(ctx, client, tmp)
	if err != nil {
		return err
	}

	backup := target + ".bak-" + time.Now().Format("20060102-150405")
	if err = copyFile(target, backup, 0o755); err != nil {
		return fmt.Errorf("备份当前二进制失败：%w", err)
	}

	replaceErr := os.Rename(binaryPath, target)
	if replaceErr != nil {
		// Rename across filesystems is not expected here (same directory), but a
		// copy keeps the update working on unusual layouts.
		replaceErr = copyFile(binaryPath, target, 0o755)
	}
	if replaceErr != nil {
		return fmt.Errorf("替换二进制失败：%w", replaceErr)
	}

	if err = restartService(ctx, service); err != nil {
		// Roll back so a broken build never leaves the panel offline.
		if restoreErr := copyFile(backup, target, 0o755); restoreErr == nil {
			_ = restartService(ctx, service)
		}
		return fmt.Errorf("新版本启动失败，已回滚：%w", err)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src) // #nosec G304 -- caller supplies a path derived from the fixed install location.
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode) // #nosec G304 -- same as above.
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// restartService restarts the unit and waits for it to report active.
func restartService(ctx context.Context, service string) error {
	if service == "" {
		service = "meridian"
	}
	run := func(args ...string) error {
		cmd := exec.CommandContext(ctx, "systemctl", args...) // #nosec G204 -- fixed verbs and a constant unit name.
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	if err := run("restart", service); err != nil {
		return err
	}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
		cmd := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", service) // #nosec G204 -- constant unit name.
		if err := cmd.Run(); err == nil {
			return nil
		}
	}
	return errors.New("服务在 45 秒内未进入 active 状态")
}

// selfBuildInfo reports whether the fork channel is reachable. It only reads
// the release manifest; nothing is downloaded until the operator confirms.
func selfBuildInfo(ctx context.Context) *selfBuildRelease {
	info := &selfBuildRelease{URL: selfBuildBinaryURL}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, selfBuildChecksumURL, nil)
	if err != nil {
		info.Reason = err.Error()
		return info
	}
	req.Header.Set("User-Agent", "Meridian/"+appVersion)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		info.Reason = "无法连接 GitHub，请稍后重试"
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		info.Reason = fmt.Sprintf("自用版发布通道返回 HTTP %d", resp.StatusCode)
		return info
	}
	info.Supported = true
	info.Available = true
	return info
}
