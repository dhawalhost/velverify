package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"go.uber.org/zap"
)

// Handler handles a specific MCP method.
type Handler func(ctx context.Context, params json.RawMessage) (interface{}, error)

// Server implements the MCP server over a provided transport.
type Server struct {
	name     string
	version  string
	handlers map[string]Handler
	logger   *zap.Logger
	mu       sync.RWMutex
}

// NewServer creates a new MCP server.
func NewServer(name, version string, logger *zap.Logger) *Server {
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &Server{
		name:     name,
		version:  version,
		handlers: make(map[string]Handler),
		logger:   logger,
	}

	// Register built-in methods
	s.RegisterHandler("initialize", s.handleInitialize)
	s.RegisterHandler("notifications/initialized", s.handleInitialized)

	return s
}

// RegisterHandler registers a handler for an MCP method.
func (s *Server) RegisterHandler(method string, handler Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handlers[method] = handler
}

// Serve starts the JSON-RPC loop on stdin/stdout.
func (s *Server) Serve() error {
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			s.sendError(nil, -32700, "Parse error", nil)
			continue
		}

		go s.handleRequest(req)
	}
}

func (s *Server) handleRequest(req Request) {
	s.mu.RLock()
	handler, ok := s.handlers[req.Method]
	s.mu.RUnlock()

	if !ok {
		s.sendError(req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method), nil)
		return
	}

	ctx := context.Background()
	result, err := handler(ctx, req.Params)
	if err != nil {
		s.sendError(req.ID, -32603, err.Error(), nil)
		return
	}

	if req.ID != nil {
		s.sendResponse(req.ID, result)
	}
}

func (s *Server) sendResponse(id interface{}, result interface{}) {
	resp := Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  result,
	}
	s.write(resp)
}

func (s *Server) sendError(id interface{}, code int, message string, data interface{}) {
	resp := Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error: &RPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
	}
	s.write(resp)
}

func (s *Server) write(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		s.logger.Error("Failed to marshal response", zap.Error(err))
		return
	}
	fmt.Fprintf(os.Stdout, "%s\n", data)
}

// Built-in handlers

func (s *Server) handleInitialize(ctx context.Context, params json.RawMessage) (interface{}, error) {
	return map[string]interface{}{
		"protocolVersion": "2024-11-05", // Latest MCP version
		"capabilities": map[string]interface{}{
			"tools": map[string]interface{}{},
		},
		"serverInfo": map[string]string{
			"name":    s.name,
			"version": s.version,
		},
	}, nil
}

func (s *Server) handleInitialized(ctx context.Context, params json.RawMessage) (interface{}, error) {
	// Acknowledge initialization
	return nil, nil
}
