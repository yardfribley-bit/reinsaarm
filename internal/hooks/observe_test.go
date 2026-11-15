package hooks

import (
	"strings"
	"testing"
)

func TestDecisionEvents(t *testing.T) {
	for _, e := range []string{"", "PreToolUse", "BeforeTool"} {
		if !IsDecisionEvent(e) {
			t.Fatalf("%q must decide", e)
		}
	}
	for _, e := range []string{"PostToolUse", "PostToolUseFailure", "AfterTool", "SessionStart", "SessionEnd", "UserPromptSubmit", "BeforeAgent", "AfterAgent", "Stop", "Notification"} {
		if IsDecisionEvent(e) {
			t.Fatalf("%q must only observe", e)
		}
	}
	if !Observes(ClientCodex, "PostToolUse") || Observes(ClientCodex, "PostToolUseFailure") || !Observes(ClientGemini, "AfterTool") {
		t.Fatal("observed events")
	}
	if NeutralOutput(ClientCodex) != nil || string(NeutralOutput(ClientGemini)) != "{}\n" {
		t.Fatal("neutral output")
	}
}

func TestObserveRequestClips(t *testing.T) {
	big := strings.Repeat("日志", 5000)
	req := ObserveRequest(ClientWorkBuddy, map[string]any{
		"session_id": "s", "cwd": "/p", "hook_event_name": "PostToolUse", "tool_name": "Read",
		"tool_input": map[string]any{"file_path": "/p/a.txt"}, "call_id": "tc_1",
		"tool_response": map[string]any{"content": big}, "session": map[string]any{"id": "x"},
	})
	if req.Schema != SchemaObserve || req.Event != "PostToolUse" || req.ToolUseID != "tc_1" || req.Tool != "Read" {
		t.Fatalf("%+v", req)
	}
	if _, ok := req.Payload["tool_input"]; ok {
		t.Fatal("tool_input travels in Input, not Payload")
	}
	got := req.Payload["tool_response"].(map[string]any)["content"].(string)
	if len(got) > clipString+4 || !strings.HasSuffix(got, "…") {
		t.Fatalf("not clipped: %d", len(got))
	}
}
