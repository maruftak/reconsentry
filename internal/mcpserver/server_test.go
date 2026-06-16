package mcpserver

import (
	"context"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/maruftak/reconsentry/internal/store"
)

// call invokes a registered tool handler with the given arguments, exercising
// the same path the MCP SDK takes (argument parsing -> data fetch -> JSON
// result) without standing up a stdio transport.
func call(t *testing.T, h func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error), args map[string]any) *mcp.CallToolResult {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Arguments = args
	res, err := h(context.Background(), req)
	if err != nil {
		t.Fatalf("handler returned a transport error (should surface tool errors in the result): %v", err)
	}
	if res == nil {
		t.Fatal("handler returned a nil result")
	}
	return res
}

func TestNewRegistersFourTools(t *testing.T) {
	st := seed(t)
	s := New(st, "test")
	for _, name := range []string{"list_scopes", "list_assets", "list_history", "get_changes"} {
		if s.GetTool(name) == nil {
			t.Errorf("tool %q not registered", name)
		}
	}
}

func TestHandlersHappyPath(t *testing.T) {
	st := seed(t)

	if res := call(t, handleListScopes(st), nil); res.IsError {
		t.Errorf("list_scopes should succeed, got error result: %+v", res)
	}
	if res := call(t, handleListAssets(st), map[string]any{"scope": "acme", "filter": "admin"}); res.IsError {
		t.Errorf("list_assets should succeed, got %+v", res)
	}
	if res := call(t, handleListHistory(st), map[string]any{"scope": "acme"}); res.IsError {
		t.Errorf("list_history should succeed, got %+v", res)
	}
	// get_changes with a word priority arg exercises the prioritize.Level mapping.
	res := call(t, handleGetChanges(st), map[string]any{"scope": "acme", "min_priority": "high"})
	if res.IsError {
		t.Errorf("get_changes should succeed, got %+v", res)
	}
	cs, ok := res.StructuredContent.(ChangeSet)
	if !ok {
		t.Fatalf("get_changes structured content is %T, want ChangeSet", res.StructuredContent)
	}
	for _, c := range cs.Changes {
		if c.Priority < 3 { // diff.High
			t.Errorf("min_priority=high leaked a low change through the handler: %+v", c)
		}
	}
}

func TestHandlersErrorsAreToolErrors(t *testing.T) {
	st := seed(t)

	// An unknown scope must come back as a tool error (IsError), not a Go error,
	// so the agent can read and recover from it.
	for name, h := range map[string]func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error){
		"list_assets":  handleListAssets(st),
		"list_history": handleListHistory(st),
		"get_changes":  handleGetChanges(st),
	} {
		res := call(t, h, map[string]any{"scope": "ghost"})
		if !res.IsError {
			t.Errorf("%s on unknown scope: want IsError result, got %+v", name, res)
		}
	}
}

func TestHandlerErrorOnEmptyDB(t *testing.T) {
	// An empty (but openable) database must not panic; tools that need a scope
	// return a clear tool error.
	st, err := store.Open(t.TempDir() + "/empty.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if res := call(t, handleListScopes(st), nil); res.IsError {
		t.Errorf("list_scopes on empty db should succeed with an empty list, got %+v", res)
	}
	if res := call(t, handleListAssets(st), nil); !res.IsError {
		t.Errorf("list_assets on empty db should be a tool error, got %+v", res)
	}
}
