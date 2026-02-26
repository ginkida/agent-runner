package tools

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ginkida/agent-runner/internal/agent"
)

// BuiltinFactory creates a tool given a work directory and session ID.
type BuiltinFactory func(workDir, sessionID string) agent.Tool

// Builtins maps tool names to their factory functions.
var Builtins = map[string]BuiltinFactory{
	"read_file":  func(wd, _ string) agent.Tool { return &readFileTool{workDir: wd} },
	"write_file": func(wd, _ string) agent.Tool { return &writeFileTool{workDir: wd} },
	"edit_file":  func(wd, _ string) agent.Tool { return &editFileTool{workDir: wd} },
	"bash":       func(wd, sid string) agent.Tool { return &bashTool{workDir: wd, sessionID: sid} },
	"glob":       func(wd, _ string) agent.Tool { return &globTool{workDir: wd} },
	"grep":       func(wd, _ string) agent.Tool { return &grepTool{workDir: wd} },
	"list_dir":   func(wd, _ string) agent.Tool { return &listDirTool{workDir: wd} },
}

// sandboxPath resolves a requested path and ensures it falls within workDir.
// It handles symlinks and paths that don't exist yet (for write operations).
func sandboxPath(workDir, requestedPath string) (string, error) {
	if workDir == "" {
		return "", fmt.Errorf("work directory not configured")
	}
	if !filepath.IsAbs(requestedPath) {
		requestedPath = filepath.Join(workDir, requestedPath)
	}
	resolved, err := filepath.EvalSymlinks(requestedPath)
	if err != nil {
		// File doesn't exist yet (write) — resolve parent
		parent := filepath.Dir(requestedPath)
		rp, err2 := filepath.EvalSymlinks(parent)
		if err2 != nil {
			resolved = filepath.Clean(requestedPath)
		} else {
			resolved = filepath.Join(rp, filepath.Base(requestedPath))
		}
	}
	resolvedWD, _ := filepath.EvalSymlinks(workDir)
	if resolvedWD == "" {
		resolvedWD = filepath.Clean(workDir)
	}
	if resolved != resolvedWD && !strings.HasPrefix(resolved, resolvedWD+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q is outside work directory", requestedPath)
	}

	// Check sensitive path blocklist
	for _, sp := range sensitivePaths {
		if strings.Contains(resolved, sp) {
			return "", fmt.Errorf("access to sensitive path %q is blocked", sp)
		}
	}

	return resolved, nil
}

// dangerousPatterns matches bash commands that should never be executed.
var dangerousPatterns = regexp.MustCompile(
	`(?i)` +
		`(rm\s+-[^\s]*r[^\s]*f|rm\s+-[^\s]*f[^\s]*r)` + // rm -rf variants
		`|mkfs\.` + // filesystem format
		`|dd\s+(if=|of=)` + // raw disk write
		`|:\(\)\{.*\|.*&.*\};:` + // fork bomb
		`|shutdown\b|reboot\b|poweroff\b|halt\b` + // system control
		`|(curl|wget)[^|]*\|\s*(ba)?sh` + // pipe to shell
		`|>\s*/dev/(sd|nvme|hd|xvd)` + // write to raw device
		`|chmod\s+-R\s+777\s+/\s*$` + // recursive chmod 777 /
		`|iptables\b|nftables\b|firewall-cmd\b` + // firewall manipulation
		`|(eval|exec)\s+\$\(` + // eval/exec with command substitution
		`|base64\s+-d.*\|\s*(ba)?sh` + // base64 decode to shell
		`|python[23]?\s+-c\s` + // python -c (inline code with network access)
		`|ruby\s+-e\s` + // ruby -e
		`|perl\s+-e\s` + // perl -e
		`|node\s+-e\s` + // node -e
		`|/dev/tcp/` + // bash /dev/tcp built-in
		`|/dev/udp/`, // bash /dev/udp built-in
)

// blockedNetworkCmds are commands that perform network I/O. The agent should
// not be allowed to exfiltrate data or make arbitrary network connections.
var blockedNetworkCmds = []string{
	"curl", "wget", "nc", "ncat", "netcat",
	"ssh", "scp", "sftp", "telnet", "ftp",
	"rsync", "socat",
}

// sensitivePaths that should never be read or written by the agent.
var sensitivePaths = []string{
	"/.ssh/",
	"/.aws/",
	"/.config/gcloud/",
	"/etc/shadow",
	"/etc/sudoers",
	"/.kube/",
	"/.docker/config.json",
}

// isDangerousCommand checks if a bash command matches the deny-list.
func isDangerousCommand(cmd string) (bool, string) {
	if loc := dangerousPatterns.FindStringIndex(cmd); loc != nil {
		return true, fmt.Sprintf("blocked dangerous pattern: %s", cmd[loc[0]:loc[1]])
	}

	// Check each command segment for blocked network commands.
	// Split on pipe, semicolon, ampersand, and newline to get individual commands.
	segments := splitCommandSegments(cmd)
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		// Get the first word of the segment (the command name)
		firstWord := strings.Fields(seg)[0]
		// Strip any path prefix (e.g. /usr/bin/curl → curl)
		firstWord = filepath.Base(firstWord)
		for _, blocked := range blockedNetworkCmds {
			if firstWord == blocked {
				return true, fmt.Sprintf("blocked network command: %s", blocked)
			}
		}
	}

	// Check for sensitive paths in the command
	for _, sp := range sensitivePaths {
		if strings.Contains(cmd, sp) {
			return true, fmt.Sprintf("blocked access to sensitive path: %s", sp)
		}
	}

	return false, ""
}

// splitCommandSegments splits a shell command string on |, ;, &&, || and newlines.
func splitCommandSegments(cmd string) []string {
	var segments []string
	var current strings.Builder
	i := 0
	for i < len(cmd) {
		ch := cmd[i]
		switch ch {
		case '|':
			segments = append(segments, current.String())
			current.Reset()
			if i+1 < len(cmd) && cmd[i+1] == '|' {
				i++ // skip ||
			}
		case ';', '\n':
			segments = append(segments, current.String())
			current.Reset()
		case '&':
			segments = append(segments, current.String())
			current.Reset()
			if i+1 < len(cmd) && cmd[i+1] == '&' {
				i++ // skip &&
			}
		default:
			current.WriteByte(ch)
		}
		i++
	}
	if current.Len() > 0 {
		segments = append(segments, current.String())
	}
	return segments
}

// wrapWithLimits prepends resource limits to a bash command.
func wrapWithLimits(cmd string) string {
	// -u 64: max 64 user processes (blocks fork bombs)
	// -f 10240: max 10MB file writes (in 1024-byte blocks)
	// -v 524288: max 512MB virtual memory (in KB)
	return "ulimit -u 64 -f 10240 -v 524288 2>/dev/null; " + cmd
}

// limitedWriter caps writes at a byte limit, silently discarding overflow.
type limitedWriter struct {
	buf       *bytes.Buffer
	limit     int
	truncated bool
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if remaining <= 0 {
		w.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		w.truncated = true
		p = p[:remaining]
	}
	return w.buf.Write(p)
}

const maxOutputBytes = 100 * 1024 // 100KB cap for bash output

// BuiltinNames returns all available builtin tool names.
func BuiltinNames() []string {
	names := make([]string, 0, len(Builtins))
	for name := range Builtins {
		names = append(names, name)
	}
	return names
}

// --- read_file ---

type readFileTool struct{ workDir string }

func (t *readFileTool) Name() string        { return "read_file" }
func (t *readFileTool) Description() string { return "Read the contents of a file. Returns numbered lines." }
func (t *readFileTool) Declaration() *agent.FunctionDeclaration {
	return &agent.FunctionDeclaration{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &agent.Schema{
			Type: agent.TypeObject,
			Properties: map[string]*agent.Schema{
				"file_path": {Type: agent.TypeString, Description: "Absolute path to the file"},
				"offset":    {Type: agent.TypeInteger, Description: "Line number to start from (1-based)"},
				"limit":     {Type: agent.TypeInteger, Description: "Maximum number of lines to read"},
			},
			Required: []string{"file_path"},
		},
	}
}

func (t *readFileTool) Execute(_ context.Context, args map[string]any) (*agent.ToolResult, error) {
	path, ok := agent.GetString(args, "file_path")
	if !ok {
		return agent.NewErrorResult("file_path is required"), nil
	}
	safePath, err := sandboxPath(t.workDir, path)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	path = safePath
	info, err := os.Stat(path)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	const maxReadSize = 10 << 20 // 10MB
	if info.Size() > maxReadSize {
		return agent.NewErrorResult(fmt.Sprintf("file too large: %s (%d bytes, max %d)", path, info.Size(), maxReadSize)), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	lines := strings.Split(string(data), "\n")
	offset := agent.GetIntDefault(args, "offset", 1)
	limit := agent.GetIntDefault(args, "limit", 0)
	if offset < 1 {
		offset = 1
	}
	start := offset - 1
	if start > len(lines) {
		start = len(lines)
	}
	end := len(lines)
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	var buf strings.Builder
	for i := start; i < end; i++ {
		fmt.Fprintf(&buf, "%6d\t%s\n", i+1, lines[i])
	}
	return agent.NewSuccessResult(buf.String()), nil
}

// --- write_file ---

type writeFileTool struct{ workDir string }

func (t *writeFileTool) Name() string        { return "write_file" }
func (t *writeFileTool) Description() string { return "Write content to a file, creating directories as needed." }
func (t *writeFileTool) Declaration() *agent.FunctionDeclaration {
	return &agent.FunctionDeclaration{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &agent.Schema{
			Type: agent.TypeObject,
			Properties: map[string]*agent.Schema{
				"file_path": {Type: agent.TypeString, Description: "Absolute path to the file"},
				"content":   {Type: agent.TypeString, Description: "Content to write"},
			},
			Required: []string{"file_path", "content"},
		},
	}
}

func (t *writeFileTool) Execute(_ context.Context, args map[string]any) (*agent.ToolResult, error) {
	path, _ := agent.GetString(args, "file_path")
	content, _ := agent.GetString(args, "content")
	if path == "" {
		return agent.NewErrorResult("file_path is required"), nil
	}
	safePath, err := sandboxPath(t.workDir, path)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	path = safePath
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	return agent.NewSuccessResult(fmt.Sprintf("Wrote %d bytes to %s", len(content), path)), nil
}

// --- edit_file ---

type editFileTool struct{ workDir string }

func (t *editFileTool) Name() string        { return "edit_file" }
func (t *editFileTool) Description() string { return "Edit a file by replacing exact string matches." }
func (t *editFileTool) Declaration() *agent.FunctionDeclaration {
	return &agent.FunctionDeclaration{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &agent.Schema{
			Type: agent.TypeObject,
			Properties: map[string]*agent.Schema{
				"file_path":   {Type: agent.TypeString, Description: "Absolute path to the file"},
				"old_string":  {Type: agent.TypeString, Description: "Exact string to find"},
				"new_string":  {Type: agent.TypeString, Description: "Replacement string"},
				"replace_all": {Type: agent.TypeBoolean, Description: "Replace all occurrences (default false)"},
			},
			Required: []string{"file_path", "old_string", "new_string"},
		},
	}
}

func (t *editFileTool) Execute(_ context.Context, args map[string]any) (*agent.ToolResult, error) {
	path, _ := agent.GetString(args, "file_path")
	oldStr, _ := agent.GetString(args, "old_string")
	newStr, _ := agent.GetString(args, "new_string")
	replaceAll := agent.GetBoolDefault(args, "replace_all", false)

	if path == "" || oldStr == "" {
		return agent.NewErrorResult("file_path and old_string are required"), nil
	}
	safePath, err := sandboxPath(t.workDir, path)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	path = safePath

	data, err := os.ReadFile(path)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}

	content := string(data)
	if !strings.Contains(content, oldStr) {
		return agent.NewErrorResult("old_string not found in file"), nil
	}

	var newContent string
	if replaceAll {
		newContent = strings.ReplaceAll(content, oldStr, newStr)
	} else {
		count := strings.Count(content, oldStr)
		if count > 1 {
			return agent.NewErrorResult(fmt.Sprintf("old_string found %d times; use replace_all or provide more context", count)), nil
		}
		newContent = strings.Replace(content, oldStr, newStr, 1)
	}

	if err := os.WriteFile(path, []byte(newContent), 0644); err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	return agent.NewSuccessResult("File edited successfully"), nil
}

// --- bash ---

type bashTool struct {
	workDir   string
	sessionID string
}

func (t *bashTool) Name() string        { return "bash" }
func (t *bashTool) Description() string { return "Execute a bash command and return stdout/stderr." }
func (t *bashTool) Declaration() *agent.FunctionDeclaration {
	return &agent.FunctionDeclaration{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &agent.Schema{
			Type: agent.TypeObject,
			Properties: map[string]*agent.Schema{
				"command": {Type: agent.TypeString, Description: "The bash command to execute"},
				"timeout": {Type: agent.TypeInteger, Description: "Timeout in seconds (default 120)"},
			},
			Required: []string{"command"},
		},
	}
}

func (t *bashTool) Execute(ctx context.Context, args map[string]any) (*agent.ToolResult, error) {
	command, _ := agent.GetString(args, "command")
	if command == "" {
		return agent.NewErrorResult("command is required"), nil
	}
	if dangerous, reason := isDangerousCommand(command); dangerous {
		return agent.NewErrorResult(reason), nil
	}
	timeout := agent.GetIntDefault(args, "timeout", 120)

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()

	// Wrap command with resource limits
	wrappedCmd := wrapWithLimits(command)

	cmd := exec.CommandContext(execCtx, "bash", "-c", wrappedCmd)
	cmd.Dir = t.workDir

	// Build isolated environment
	sessionTmpDir, err := t.sessionTmpDir()
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	cmd.Env = []string{
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + os.Getenv("HOME"),
		"LANG=" + os.Getenv("LANG"),
		"TERM=dumb",
		"TMPDIR=" + sessionTmpDir,
	}

	stdoutBuf := &bytes.Buffer{}
	stderrBuf := &bytes.Buffer{}
	stdoutLW := &limitedWriter{buf: stdoutBuf, limit: maxOutputBytes}
	stderrLW := &limitedWriter{buf: stderrBuf, limit: maxOutputBytes}
	cmd.Stdout = stdoutLW
	cmd.Stderr = stderrLW

	err = cmd.Run()

	var result strings.Builder
	if stdoutBuf.Len() > 0 {
		result.WriteString(stdoutBuf.String())
	}
	if stdoutLW.truncated {
		result.WriteString(fmt.Sprintf("\n... (stdout truncated at %d bytes)", maxOutputBytes))
	}
	if stderrBuf.Len() > 0 {
		if result.Len() > 0 {
			result.WriteString("\n")
		}
		result.WriteString("STDERR:\n")
		result.WriteString(stderrBuf.String())
	}
	if stderrLW.truncated {
		result.WriteString(fmt.Sprintf("\n... (stderr truncated at %d bytes)", maxOutputBytes))
	}

	if err != nil {
		if result.Len() > 0 {
			result.WriteString("\n")
		}
		result.WriteString("Exit: " + err.Error())
		return agent.NewErrorResult(result.String()), nil
	}

	output := result.String()
	if output == "" {
		output = "(no output)"
	}
	if len(output) > maxOutputBytes {
		output = output[:maxOutputBytes] + "\n... (output truncated)"
	}
	return agent.NewSuccessResult(output), nil
}

// sessionTmpDir returns a per-session temp directory, creating it if needed.
func (t *bashTool) sessionTmpDir() (string, error) {
	if t.sessionID == "" {
		return os.TempDir(), nil
	}
	dir := filepath.Join(os.TempDir(), "agent-runner", t.sessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create session tmp dir: %w", err)
	}
	return dir, nil
}

// CleanupSessionTmp removes the per-session temp directory.
func CleanupSessionTmp(sessionID string) {
	if sessionID == "" {
		return
	}
	dir := filepath.Join(os.TempDir(), "agent-runner", sessionID)
	os.RemoveAll(dir)
}

// --- glob ---

type globTool struct{ workDir string }

func (t *globTool) Name() string        { return "glob" }
func (t *globTool) Description() string { return "Find files matching a glob pattern." }
func (t *globTool) Declaration() *agent.FunctionDeclaration {
	return &agent.FunctionDeclaration{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &agent.Schema{
			Type: agent.TypeObject,
			Properties: map[string]*agent.Schema{
				"pattern": {Type: agent.TypeString, Description: "Glob pattern (e.g. **/*.go)"},
				"path":    {Type: agent.TypeString, Description: "Directory to search in"},
			},
			Required: []string{"pattern"},
		},
	}
}

func (t *globTool) Execute(_ context.Context, args map[string]any) (*agent.ToolResult, error) {
	pattern, _ := agent.GetString(args, "pattern")
	if pattern == "" {
		return agent.NewErrorResult("pattern is required"), nil
	}
	dir := agent.GetStringDefault(args, "path", t.workDir)
	if dir == "" {
		dir = t.workDir
	}
	safeDir, err := sandboxPath(t.workDir, dir)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	dir = safeDir

	// Use filepath.WalkDir to support ** (doublestar) patterns
	var matches []string
	maxMatches := 1000

	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if len(matches) >= maxMatches {
			return filepath.SkipAll
		}
		// Skip hidden dirs and common noise
		name := d.Name()
		if d.IsDir() && (name == ".git" || name == "node_modules" || name == "vendor" || name == ".idea") {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		if matchGlob(pattern, rel) {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}

	if len(matches) == 0 {
		return agent.NewSuccessResult("No files found"), nil
	}

	return agent.NewSuccessResult(strings.Join(matches, "\n")), nil
}

// matchGlob supports ** doublestar patterns by splitting on ** segments.
func matchGlob(pattern, name string) bool {
	// Normalize separators
	pattern = filepath.ToSlash(pattern)
	name = filepath.ToSlash(name)

	parts := strings.Split(pattern, "**")
	if len(parts) == 1 {
		// No **, use standard match
		ok, _ := filepath.Match(pattern, name)
		return ok
	}

	// Match ** as "any path segment(s)"
	// e.g. "**/*.go" → parts=["", "/*.go"]
	// e.g. "src/**/*.go" → parts=["src/", "/*.go"]
	return matchDoublestar(parts, name)
}

func matchDoublestar(parts []string, name string) bool {
	if len(parts) == 0 {
		return true
	}
	if len(parts) == 1 {
		ok, _ := filepath.Match(parts[0], name)
		return ok
	}

	first := parts[0]
	rest := parts[1:]

	if first == "" {
		// Leading ** — try matching rest against every suffix
		for i := 0; i <= len(name); i++ {
			suffix := name[i:]
			restPattern := strings.TrimPrefix(rest[0], "/")
			if len(rest) == 1 {
				ok, _ := filepath.Match(restPattern, suffix)
				if ok {
					return true
				}
			} else {
				newRest := append([]string{restPattern}, rest[1:]...)
				if matchDoublestar(newRest, suffix) {
					return true
				}
			}
		}
		return false
	}

	// first is a prefix before **, name must start matching it
	// Try each position as where ** ends
	for i := len(first); i <= len(name); i++ {
		prefix := name[:i]
		ok, _ := filepath.Match(strings.TrimSuffix(first, "/"), strings.TrimSuffix(prefix, "/"))
		if ok {
			remaining := name[i:]
			if len(remaining) > 0 && remaining[0] == '/' {
				remaining = remaining[1:]
			}
			if matchDoublestar(rest, remaining) {
				return true
			}
		}
	}
	return false
}

// --- grep ---

type grepTool struct{ workDir string }

func (t *grepTool) Name() string        { return "grep" }
func (t *grepTool) Description() string { return "Search file contents using regex patterns." }
func (t *grepTool) Declaration() *agent.FunctionDeclaration {
	return &agent.FunctionDeclaration{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &agent.Schema{
			Type: agent.TypeObject,
			Properties: map[string]*agent.Schema{
				"pattern": {Type: agent.TypeString, Description: "Regex pattern to search for"},
				"path":    {Type: agent.TypeString, Description: "File or directory to search in"},
				"include": {Type: agent.TypeString, Description: "File glob filter (e.g. *.go)"},
			},
			Required: []string{"pattern"},
		},
	}
}

// skipDirs are directories that grep should never descend into.
var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
	".idea": true, ".vscode": true, "__pycache__": true,
	".mypy_cache": true, ".tox": true, "dist": true,
}

func (t *grepTool) Execute(ctx context.Context, args map[string]any) (*agent.ToolResult, error) {
	pattern, _ := agent.GetString(args, "pattern")
	if pattern == "" {
		return agent.NewErrorResult("pattern is required"), nil
	}
	searchPath := agent.GetStringDefault(args, "path", t.workDir)
	safePath, err := sandboxPath(t.workDir, searchPath)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	searchPath = safePath
	include, _ := agent.GetString(args, "include")

	re, err := regexp.Compile(pattern)
	if err != nil {
		return agent.NewErrorResult(fmt.Sprintf("invalid regex: %v", err)), nil
	}

	var results strings.Builder
	count := 0
	maxResults := 100

	err = filepath.WalkDir(searchPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= maxResults {
			return filepath.SkipAll
		}
		// Skip files > 1MB (likely binary)
		if info, err := d.Info(); err == nil && info.Size() > 1<<20 {
			return nil
		}
		if include != "" {
			matched, _ := filepath.Match(include, filepath.Base(path))
			if !matched {
				return nil
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		// Skip binary files (contains null bytes in first 512 bytes)
		sample := data
		if len(sample) > 512 {
			sample = sample[:512]
		}
		if bytes.ContainsRune(sample, 0) {
			return nil
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if re.MatchString(line) {
				fmt.Fprintf(&results, "%s:%d:%s\n", path, i+1, line)
				count++
				if count >= maxResults {
					return nil
				}
			}
		}
		return nil
	})

	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	if count == 0 {
		return agent.NewSuccessResult("No matches found"), nil
	}
	return agent.NewSuccessResult(results.String()), nil
}

// --- list_dir ---

type listDirTool struct{ workDir string }

func (t *listDirTool) Name() string        { return "list_dir" }
func (t *listDirTool) Description() string { return "List contents of a directory." }
func (t *listDirTool) Declaration() *agent.FunctionDeclaration {
	return &agent.FunctionDeclaration{
		Name:        t.Name(),
		Description: t.Description(),
		Parameters: &agent.Schema{
			Type: agent.TypeObject,
			Properties: map[string]*agent.Schema{
				"path": {Type: agent.TypeString, Description: "Directory path to list"},
			},
			Required: []string{"path"},
		},
	}
}

func (t *listDirTool) Execute(_ context.Context, args map[string]any) (*agent.ToolResult, error) {
	path := agent.GetStringDefault(args, "path", t.workDir)
	if path == "" {
		path = t.workDir
	}
	safePath, err := sandboxPath(t.workDir, path)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}
	path = safePath

	entries, err := os.ReadDir(path)
	if err != nil {
		return agent.NewErrorResult(err.Error()), nil
	}

	var buf strings.Builder
	for _, entry := range entries {
		info, _ := entry.Info()
		suffix := ""
		if entry.IsDir() {
			suffix = "/"
		}
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		fmt.Fprintf(&buf, "%s%s\t%d\n", entry.Name(), suffix, size)
	}
	return agent.NewSuccessResult(buf.String()), nil
}
