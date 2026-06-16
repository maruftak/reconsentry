package mcpserver

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/maruftak/reconsentry/internal/prioritize"
	"github.com/maruftak/reconsentry/internal/store"
)

// New builds a read-only MCP server over an already-opened snapshot store. The
// store should be opened with store.OpenReadOnly so the protocol surface cannot
// mutate collected data. version is reported to the client in the handshake.
//
// Every registered tool is annotated read-only and idempotent: it performs a
// pure database read and never scans, probes, resolves, or writes.
func New(st *store.Store, version string) *server.MCPServer {
	s := server.NewMCPServer(
		"reconsentry",
		version,
		server.WithToolCapabilities(false),
		server.WithInstructions(
			"reconsentry exposes an already-collected attack-surface snapshot database, "+
				"read-only. Use list_scopes to see what targets are stored, list_assets for the "+
				"current hosts of a scope, list_history for its recorded runs, and get_changes to "+
				"see what changed between two runs. These tools never scan, probe, or modify "+
				"anything — they only report data reconsentry has already gathered.",
		),
	)

	s.AddTool(
		mcp.NewTool("list_scopes",
			mcp.WithDescription("List the scope (target program) names present in the snapshot database."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
		),
		handleListScopes(st),
	)

	s.AddTool(
		mcp.NewTool("list_assets",
			mcp.WithDescription("List the hosts in the latest snapshot of a scope, with liveness, HTTP status, IP, and detected technologies."),
			mcp.WithString("scope", mcp.Description("Scope name. Optional when the database holds a single scope.")),
			mcp.WithString("filter", mcp.Description("Optional case-insensitive substring; keeps only hosts whose name contains it.")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
		),
		handleListAssets(st),
	)

	s.AddTool(
		mcp.NewTool("list_history",
			mcp.WithDescription("List the recorded monitoring runs for a scope (run id, timestamp, asset count), most recent first."),
			mcp.WithString("scope", mcp.Description("Scope name. Optional when the database holds a single scope.")),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
		),
		handleListHistory(st),
	)

	s.AddTool(
		mcp.NewTool("get_changes",
			mcp.WithDescription("Show attack-surface changes for a scope, computed from stored snapshots: by default the latest run versus the previous one, or between two given run ids. Each change has a kind (e.g. NEW_HOST, HOST_GONE, NEW_TECH, STATUS_CHANGE), host, priority, and detail."),
			mcp.WithString("scope", mcp.Description("Scope name. Optional when the database holds a single scope.")),
			mcp.WithNumber("from_run_id", mcp.Description("Older run id to diff from. Provide together with to_run_id, or omit both to use the latest two runs.")),
			mcp.WithNumber("to_run_id", mcp.Description("Newer run id to diff to. Provide together with from_run_id, or omit both to use the latest two runs.")),
			mcp.WithString("min_priority",
				mcp.Description("Minimum priority to include: low | medium | high. Defaults to low (all changes)."),
				mcp.Enum("low", "medium", "high"),
			),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithIdempotentHintAnnotation(true),
		),
		handleGetChanges(st),
	)

	return s
}

// Serve runs the read-only MCP server over stdio until the client disconnects
// or the process is signalled. It blocks.
func Serve(st *store.Store, version string) error {
	return server.ServeStdio(New(st, version))
}

func handleListScopes(st *store.Store) server.ToolHandlerFunc {
	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scopes, err := ListScopes(st)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		// Wrap in an object so the result is self-describing for the client.
		return jsonResult(struct {
			Count  int      `json:"count"`
			Scopes []string `json:"scopes"`
		}{Count: len(scopes), Scopes: scopes})
	}
}

func handleListAssets(st *store.Store) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scope := mcp.ParseString(req, "scope", "")
		filter := mcp.ParseString(req, "filter", "")
		out, err := ListAssets(st, scope, filter)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return jsonResult(out)
	}
}

func handleListHistory(st *store.Store) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scope := mcp.ParseString(req, "scope", "")
		out, err := ListHistory(st, scope)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return jsonResult(out)
	}
}

func handleGetChanges(st *store.Store) server.ToolHandlerFunc {
	return func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		scope := mcp.ParseString(req, "scope", "")
		from := int64(mcp.ParseInt(req, "from_run_id", 0))
		to := int64(mcp.ParseInt(req, "to_run_id", 0))
		// min_priority arrives as a word (low|medium|high); map it to the same
		// numeric threshold the monitor uses. Empty/unknown => low (no filter).
		minPriority := 0
		if mp := mcp.ParseString(req, "min_priority", ""); mp != "" {
			minPriority = prioritize.Level(mp)
		}
		out, err := GetChanges(st, scope, from, to, minPriority)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return jsonResult(out)
	}
}

// jsonResult renders v as a structured JSON tool result. A marshalling failure
// is surfaced as a tool error rather than a panic.
func jsonResult(v any) (*mcp.CallToolResult, error) {
	res, err := mcp.NewToolResultJSON(v)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to encode result: %v", err)), nil
	}
	return res, nil
}
