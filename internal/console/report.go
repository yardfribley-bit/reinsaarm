package console

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yardfribley-bit/reinsaarm/internal/identity"
	"github.com/yardfribley-bit/reinsaarm/internal/ledger"
)

// ChainCheck is the result of verifying the whole audit chain.
type ChainCheck struct {
	OK    bool   `json:"ok"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

func (s *Server) chainCheck() ChainCheck {
	pub, err := identity.LoadPublic(s.cfg.IdentityKey)
	if err != nil {
		return ChainCheck{Error: err.Error()}
	}
	n, problem, err := ledger.Verify(s.cfg.AuditPath, pub)
	if err != nil {
		return ChainCheck{Count: n, Error: err.Error()}
	}
	if problem != nil {
		return ChainCheck{Count: n, Error: fmt.Sprintf("seq %d: %s", problem.Seq, problem.Reason)}
	}
	return ChainCheck{OK: true, Count: n}
}

// turnReport writes one turn as a Markdown or JSON download.
// GET /api/sessions/{key}/report?turn=N&format=md|json&tz=Asia/Shanghai
func (s *Server) turnReport(w http.ResponseWriter, r *http.Request, sum *SessionSummary, turns []Turn) {
	if len(turns) == 0 {
		http.Error(w, "session has no turns", http.StatusNotFound)
		return
	}
	idx := len(turns)
	if v := r.URL.Query().Get("turn"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			http.Error(w, "bad turn", http.StatusBadRequest)
			return
		}
		if n < 1 || n > len(turns) {
			http.Error(w, "no such turn", http.StatusNotFound)
			return
		}
		idx = n
	}
	t := turns[idx-1]
	loc := time.Local
	if tz := r.URL.Query().Get("tz"); tz != "" {
		if l, err := time.LoadLocation(tz); err == nil {
			loc = l
		}
	}
	chain := s.chainCheck()
	base := fmt.Sprintf("reinsaarm-task-%s-%s-%d", sum.Client, shortID(sum.SessionID), idx)
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+base+`.json"`)
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"schema": "reinsaarm.task_report.v1", "generated_at": time.Now().UTC().Format(time.RFC3339),
			"session": sum, "turn": t, "chain": chain,
		})
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+base+`.md"`)
	_, _ = w.Write([]byte(reportMarkdown(sum, t, len(turns), chain, loc)))
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func localTS(ts string, loc *time.Location) string {
	t := parseTS(ts)
	if t.IsZero() {
		return ts
	}
	return t.In(loc).Format("2006-01-02 15:04:05")
}

func durText(ms int64) string {
	if ms < 1000 {
		return fmt.Sprintf("%dms", ms)
	}
	sec := ms / 1000
	if sec < 60 {
		if ms < 10000 {
			return fmt.Sprintf("%.1fs", float64(ms)/1000)
		}
		return fmt.Sprintf("%d秒", sec)
	}
	if sec < 3600 {
		return fmt.Sprintf("%d分%d秒", sec/60, sec%60)
	}
	return fmt.Sprintf("%d时%d分", sec/3600, sec/60%60)
}

func mdCell(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func reportMarkdown(sum *SessionSummary, t Turn, total int, chain ChainCheck, loc *time.Location) string {
	var b strings.Builder
	zone := loc.String()
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	p("# ReinsAARM 任务报告 · %s · %s · 任务 %d / %d\n\n", agentLabel(sum.Client), sum.Project, t.Index, total)
	p("- 会话：`%s`\n", sum.SessionID)
	p("- 项目目录：`%s`\n", sum.CWD)
	p("- 来源：%s", t.SourceLabel)
	if t.SourceWhy != "" {
		p("（%s）", t.SourceWhy)
	}
	p("\n")
	if t.Model != "" {
		p("- 模型：%s\n", t.Model)
	}
	end := t.End
	if t.Status == "running" {
		end = "进行中"
	} else {
		end = localTS(end, loc)
	}
	p("- 时间（%s）：%s → %s，%s\n", zone, localTS(t.Start, loc), end, durText(t.DurationMS))
	status := map[string]string{"running": "进行中", "done": "本轮结束", "no_stop": "未收到 Stop"}[t.Status]
	p("- 状态：%s\n", status)
	p("- 审计回执：seq %d–%d；整条链校验：", t.SeqFrom, t.SeqTo)
	if chain.OK {
		p("通过（%d 条）\n\n", chain.Count)
	} else {
		p("未通过（%s）\n\n", chain.Error)
	}
	p("## 用户原话\n\n")
	label := "原文"
	if t.PromptTruncated {
		label = "摘要（已截断）"
	}
	p("%s，%d 字，已打码：\n\n> %s\n\n", label, t.PromptChars, strings.ReplaceAll(t.Prompt, "\n", "\n> "))
	p("## 本轮实际动作\n\n%s\n\n", t.OneLiner)
	if len(t.Risks) > 0 {
		p("## 风险标记\n\n")
		for _, r := range t.Risks {
			p("- %s ×%d（seq %s）\n", r.Label, r.Count, joinSeqs(r.Seqs))
		}
		p("\n")
	}
	p("## 步骤\n\n| 时间 | # | 类型 | 内容 | 判定 | 命中规则 | 耗时 | 结果 |\n|---|---|---|---|---|---|---|---|\n")
	for _, st := range t.Steps {
		if st.Type != "tool" {
			continue
		}
		d := st.Decision
		dec, rules := "（无执行前决定）", ""
		if d != nil {
			dec = d.EnforcedDecision
			rules = strings.Join(d.RuleIDs, ", ")
		}
		what := st.Label
		if st.Query != "" {
			what += " · 搜索「" + st.Query + "」"
		}
		for _, pi := range st.Paths {
			if pi.Outside {
				what += " · 项目外 " + pi.Path
			}
		}
		dur := ""
		if st.DurationMS != nil {
			dur = durText(*st.DurationMS)
		}
		res := "已返回"
		switch {
		case st.Denied:
			res = "策略拒绝"
		case st.Failed:
			res = "执行失败"
			if st.FailHint != "" {
				res += "（" + st.FailHint + "）"
			}
		case st.Running:
			res = "进行中"
		case st.Result == nil:
			res = "无结果记录"
		case st.Result.Activity != nil && st.Result.Activity.ExitCode != nil:
			res = fmt.Sprintf("退出码 %d", *st.Result.Activity.ExitCode)
		}
		p("| %s | %d | %s | %s | %s | %s | %s | %s |\n", localTS(st.TS, loc)[11:], st.Index, st.Category, mdCell(what), dec, mdCell(rules), dur, res)
	}
	p("\n")
	if t.Untrusted > 0 {
		p("不可信输入：本轮共 %d 次网页 / 搜索结果回灌模型；", t.Untrusted)
		if t.SensitiveAfter == 0 {
			p("之后未出现敏感操作（无写文件、无改动命令、无 shell 出网）。\n\n")
		} else {
			p("之后出现 %d 次敏感操作。\n\n", t.SensitiveAfter)
		}
	}
	if len(t.Commentary) > 0 {
		p("## Agent 过程说明（来自 Agent 自己的会话记录）\n\n")
		for _, n := range t.Commentary {
			p("- %s %s\n", localTS(n.TS, loc)[11:], n.Text)
		}
		p("\n")
	}
	if t.Final != "" {
		p("## 最终回答（已打码")
		if t.FinalTruncated {
			p("，已截断，原文 %d 字", t.FinalChars)
		}
		p("）\n\n%s\n\n", t.Final)
	}
	p("## 未覆盖\n\n")
	for _, c := range coverageNotes(sum.Client, t) {
		p("- %s\n", c)
	}
	p("\n文本均已打码并截断；报告由 ReinsAARM 控制台生成。\n")
	return b.String()
}

func joinSeqs(seqs []uint64) string {
	parts := make([]string, len(seqs))
	for i, s := range seqs {
		parts[i] = strconv.FormatUint(s, 10)
	}
	return strings.Join(parts, ", ")
}

func agentLabel(c string) string {
	m := map[string]string{"codex": "Codex", "claude-code": "Claude Code", "gemini": "Gemini", "codebuddy": "CodeBuddy", "workbuddy": "WorkBuddy"}
	if v, ok := m[c]; ok {
		return v
	}
	return c
}

// coverageNotes lists what the hooks cannot see for this turn.
func coverageNotes(client string, t Turn) []string {
	var out []string
	if client == "codex" {
		out = append(out, "Codex code mode 的 exec 外层 JS 代码不会出现在时间线里（内部每次工具调用会单独记录）")
		out = append(out, "生图等内置工具尚未验证是否触发钩子，没出现在时间线里不代表没调用")
	}
	think := "模型思考过程不可见"
	if t.ThinkMS >= 1000 {
		think += "（本轮含 " + durText(t.ThinkMS) + " 无钩子事件的间隙）"
	}
	out = append(out, think)
	if !t.HasPreviews && t.Counts.Tools > 0 {
		out = append(out, "本轮回执写于参数采集上线之前，没有记录工具参数")
	}
	return out
}
