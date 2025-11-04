# Setup Guide

Complete guide for integrating oauth-mcp-proxy into your MCP server and configuring clients.

---

## Table of Contents

1. [Server Integration](#server-integration)
2. [Client Configuration](#client-configuration)
3. [Testing Your Setup](#testing-your-setup)
4. [Troubleshooting](#troubleshooting)

---

# Server Integration

Step-by-step guide for adding OAuth to your MCP server.

## Quick Start

### 1. Install Library

```bash
go get github.com/tuannvm/oauth-mcp-proxy
```

### 2. Choose Your SDK

<details>
<summary><b>mark3labs/mcp-go SDK</b></summary>

#### Import Packages

```go
import (
    "net/http"
    oauth "github.com/tuannvm/oauth-mcp-proxy"
    "github.com/tuannvm/oauth-mcp-proxy/mark3labs"
    mcpserver "github.com/mark3labs/mcp-go/server"
)
```

#### Configure OAuth

```go
mux := http.NewServeMux()

// Enable OAuth with automatic 401 handling
oauthServer, oauthOption, err := mark3labs.WithOAuth(mux, &oauth.Config{
    Provider:  "okta",                           // or "hmac", "google", "azure"
    Issuer:    "https://your-company.okta.com", // OAuth issuer URL
    Audience:  "api://your-mcp-server",         // Expected audience in tokens
    ServerURL: "https://your-server.com",       // Your server's public URL
})
if err != nil {
    log.Fatalf("Failed to setup OAuth: %v", err)
}
```

#### Create MCP Server with OAuth

```go
// Create MCP server with OAuth middleware
mcpServer := mcpserver.NewMCPServer(
    "My MCP Server",
    "1.0.0",
    oauthOption,  // ← OAuth middleware added here
)

// Add tools (all automatically protected)
mcpServer.AddTool(
    mcp.Tool{Name: "greet", Description: "Greet user"},
    func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        // Access authenticated user
        user, ok := oauth.GetUserFromContext(ctx)
        if !ok {
            return nil, fmt.Errorf("authentication required")
        }
        return mcp.NewToolResultText("Hello, " + user.Username), nil
    },
)
```

#### Setup Endpoint with Automatic 401 Handling

```go
// Create streamable server
streamableServer := mcpserver.NewStreamableHTTPServer(
    mcpServer,
    mcpserver.WithEndpointPath("/mcp"),
    mcpserver.WithHTTPContextFunc(oauth.CreateHTTPContextFunc()),
)

// Wrap endpoint with automatic 401 handling (v1.0.1+)
// Returns RFC 6750 compliant 401 responses when Bearer token is missing
mux.HandleFunc("/mcp", oauthServer.WrapMCPEndpoint(streamableServer))
```

#### Start Server

```go
log.Printf("Starting MCP server on :8080")
oauthServer.LogStartup(true) // Log OAuth endpoints
if err := http.ListenAndServe(":8080", mux); err != nil {
    log.Fatalf("Server failed: %v", err)
}
```

</details>

<details>
<summary><b>Official modelcontextprotocol/go-sdk</b></summary>

#### Import Packages

```go
import (
    "net/http"
    "github.com/modelcontextprotocol/go-sdk/mcp"
    oauth "github.com/tuannvm/oauth-mcp-proxy"
    mcpoauth "github.com/tuannvm/oauth-mcp-proxy/mcp"
)
```

#### Create MCP Server

```go
mux := http.NewServeMux()

mcpServer := mcp.NewServer(&mcp.Implementation{
    Name:    "my-server",
    Version: "1.0.0",
}, nil)

// Add tools
mcp.AddTool(mcpServer, &mcp.Tool{
    Name:        "greet",
    Description: "Greet authenticated user",
}, func(ctx context.Context, req *mcp.CallToolRequest, params *struct{}) (*mcp.CallToolResult, any, error) {
    // Access authenticated user
    user, _ := oauth.GetUserFromContext(ctx)

    return &mcp.CallToolResult{
        Content: []mcp.Content{
            &mcp.TextContent{Text: "Hello, " + user.Username},
        },
    }, nil, nil
})
```

#### Add OAuth Protection

```go
// Enable OAuth with automatic 401 handling (v1.0.1+)
oauthServer, handler, err := mcpoauth.WithOAuth(mux, &oauth.Config{
    Provider:  "okta",
    Issuer:    "https://your-company.okta.com",
    Audience:  "api://your-mcp-server",
    ServerURL: "https://your-server.com",
}, mcpServer)
if err != nil {
    log.Fatalf("Failed to setup OAuth: %v", err)
}

// The returned handler includes:
// - Automatic 401 responses with WWW-Authenticate headers
// - Token validation with caching
// - User context propagation
```

#### Start Server

```go
log.Printf("Starting MCP server on :8080")
oauthServer.LogStartup(true) // Log OAuth endpoints
if err := http.ListenAndServe(":8080", handler); err != nil {
    log.Fatalf("Server failed: %v", err)
}
```

</details>

---

## What Happens Automatically

### 1. OAuth Discovery Endpoints

When you call `WithOAuth()`, the library automatically registers these endpoints:

```
GET /.well-known/oauth-authorization-server
GET /.well-known/oauth-protected-resource
GET /.well-known/openid-configuration
```

MCP clients (like Claude Desktop) use these to **auto-discover** your OAuth configuration.

### 2. Automatic 401 Handling (v1.0.1+)

**For mark3labs SDK**: Use `WrapMCPEndpoint()` to wrap your `/mcp` endpoint:

```go
mux.HandleFunc("/mcp", oauthServer.WrapMCPEndpoint(streamableServer))
```

**For official SDK**: Automatic - the handler returned by `WithOAuth()` includes 401 handling.

**What it does:**
- ✅ Returns `401 Unauthorized` if Bearer token is missing
- ✅ Returns RFC 6750 compliant `WWW-Authenticate` headers
- ✅ Includes OAuth discovery URL in response (`resource_metadata`)
- ✅ Passes through `OPTIONS` requests (CORS pre-flight)
- ✅ Rejects non-Bearer auth schemes (only OAuth is supported)

**Example 401 response:**

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="OAuth", error="invalid_request", error_description="Bearer token required", resource_metadata="https://your-server.com/.well-known/oauth-protected-resource"
Content-Type: application/json

{"error":"invalid_request","error_description":"Bearer token required"}
```

### 3. Token Validation with Caching

Every request with a Bearer token:

1. **Extracts** token from `Authorization: Bearer <token>` header
2. **Checks cache** - tokens cached for 5 minutes (keyed by SHA-256 hash)
3. **Validates** if not cached:
   - HMAC: Verifies signature with shared secret
   - OIDC: Validates JWT against provider's JWKS
4. **Adds user to context** - available via `oauth.GetUserFromContext(ctx)`

### 4. Tool Protection

All tools registered on your MCP server are **automatically protected**:

```go
mcpServer.AddTool(myTool, myHandler)  // ← Already protected by OAuth
```

No per-tool configuration needed. If authentication fails, the request never reaches your tool handler.

---

## Accessing Authenticated User

In any tool handler, access the authenticated user from context:

```go
func myHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
    user, ok := oauth.GetUserFromContext(ctx)
    if !ok {
        return nil, fmt.Errorf("authentication required")
    }

    // User fields available:
    log.Printf("User: %s (%s)", user.Username, user.Email)
    log.Printf("Subject: %s", user.Subject)
    log.Printf("Name: %s", user.Name)

    // Use user.Subject for database queries (stable identifier)
    // Use user.Username or user.Email for display

    return mcp.NewToolResultText("Hello, " + user.Username), nil
}
```

**User struct fields:**

| Field | Description | Example |
|-------|-------------|---------|
| `Subject` | Stable user identifier (OIDC `sub`) | `"00u1abc2def3ghi4jkl"` |
| `Username` | Username or preferred_username | `"john.doe"` |
| `Email` | User's email address | `"john.doe@company.com"` |
| `Name` | Full name (if available) | `"John Doe"` |

---

## Configuration Options

### Required Fields

```go
&oauth.Config{
    Provider: "okta",      // OAuth provider: "hmac", "okta", "google", "azure"
    Issuer:   "...",       // OAuth issuer URL (provider's auth server)
    Audience: "...",       // Expected audience in tokens (your API identifier)
}
```

### Optional Fields

```go
&oauth.Config{
    ServerURL: "https://your-server.com",  // For metadata URLs (auto-detected if omitted)
    Logger:    customLogger,               // Custom logger (uses log.Printf if omitted)
    JWTSecret: []byte("..."),             // For HMAC provider only
}
```

### Provider-Specific Configuration

See provider-specific guides:
- [HMAC (Testing/Dev)](providers/HMAC.md)
- [Okta](providers/OKTA.md)
- [Google Workspace](providers/GOOGLE.md)
- [Azure AD](providers/AZURE.md)

---

# Client Configuration

How MCP clients discover and connect to OAuth-protected servers.

## Overview

When you enable OAuth on your MCP server, clients need to know:

1. **How to authenticate** - OAuth provider details
2. **Where to get tokens** - Authorization endpoints
3. **How to send tokens** - Authorization header format

This library provides **automatic discovery** via OAuth 2.0 metadata endpoints.

---

## Client Auto-Discovery (Recommended)

### How It Works

```mermaid
sequenceDiagram
    participant C as MCP Client
    participant S as Your MCP Server
    participant P as OAuth Provider

    Note over C: User adds server to client

    C->>S: GET /.well-known/oauth-authorization-server
    S->>C: OAuth metadata (issuer, endpoints, etc.)

    Note over C: Client auto-configures OAuth

    C->>P: OAuth flow (authorization code)
    P->>C: Access token

    C->>S: POST /mcp + Bearer token
    S->>C: Authenticated tool response
```

**Clients that support auto-discovery:**

- Claude Desktop (native OAuth)
- Claude Code (native OAuth)
- MCP Inspector (browser OAuth)

### Client Configuration

**Claude Desktop** (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-server.com/mcp"
    }
  }
}
```

That's it! Claude Desktop will:

1. Fetch `https://your-server.com/.well-known/oauth-authorization-server`
2. Discover OAuth issuer and endpoints
3. Guide user through OAuth flow
4. Store and manage tokens automatically

---

## Manual Client Configuration

For clients without auto-discovery:

### With Bearer Token (Pre-obtained)

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-server.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN_HERE"
      }
    }
  }
}
```

**How to get token:**

- HMAC: Generate using `jwt.NewWithClaims()` (see [HMAC Guide](providers/HMAC.md))
- OIDC: Use OAuth provider's token endpoint or admin tools

### Proxy Mode (Server Handles OAuth)

For simple clients that can't do OAuth:

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-server.com/mcp",
      "oauth": {
        "authorizationUrl": "https://your-server.com/oauth/authorize",
        "tokenUrl": "https://your-server.com/oauth/token"
      }
    }
  }
}
```

Client can now use your server's OAuth endpoints instead of going directly to the provider.

---

## Configuration By Mode

### Native Mode

**Server config (mark3labs SDK):**

```go
import "github.com/tuannvm/oauth-mcp-proxy/mark3labs"

oauthServer, oauthOption, _ := mark3labs.WithOAuth(mux, &oauth.Config{
    Provider: "okta",
    Issuer:   "https://company.okta.com",
    Audience: "api://my-server",
})
mcpServer := server.NewMCPServer("Server", "1.0.0", oauthOption)
streamable := server.NewStreamableHTTPServer(mcpServer, /*options*/)
mux.HandleFunc("/mcp", oauthServer.WrapMCPEndpoint(streamable))
```

**Server config (official SDK):**

```go
import mcpoauth "github.com/tuannvm/oauth-mcp-proxy/mcp"

mcpServer := mcp.NewServer(&mcp.Implementation{...}, nil)
_, handler, _ := mcpoauth.WithOAuth(mux, &oauth.Config{
    Provider: "okta",
    Issuer:   "https://company.okta.com",
    Audience: "api://my-server",
}, mcpServer)
```

**Client discovers:**

- Metadata endpoints return Okta URLs
- Client authenticates directly with Okta
- Client sends Okta token to your server
- Your server validates token against Okta

**Client config (auto-discovery):**

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-server.com/mcp"
    }
  }
}
```

Client fetches metadata, sees Okta issuer, handles OAuth with Okta directly.

### Proxy Mode

**Server config (mark3labs SDK):**

```go
import "github.com/tuannvm/oauth-mcp-proxy/mark3labs"

oauthServer, oauthOption, _ := mark3labs.WithOAuth(mux, &oauth.Config{
    Provider:     "okta",
    ClientID:     "...",
    ClientSecret: "...",
    ServerURL:    "https://your-server.com",
    RedirectURIs: "https://your-server.com/oauth/callback",
})
mcpServer := server.NewMCPServer("Server", "1.0.0", oauthOption)
streamable := server.NewStreamableHTTPServer(mcpServer, /*options*/)
mux.HandleFunc("/mcp", oauthServer.WrapMCPEndpoint(streamable))
```

**Server config (official SDK):**

```go
import mcpoauth "github.com/tuannvm/oauth-mcp-proxy/mcp"

mcpServer := mcp.NewServer(&mcp.Implementation{...}, nil)
_, handler, _ := mcpoauth.WithOAuth(mux, &oauth.Config{
    Provider:     "okta",
    ClientID:     "...",
    ClientSecret: "...",
    ServerURL:    "https://your-server.com",
    RedirectURIs: "https://your-server.com/oauth/callback",
}, mcpServer)
```

**Client discovers:**

- Metadata endpoints return YOUR server URLs (not Okta)
- Client authenticates through your server
- Your server proxies to Okta
- Client sends token from your server

**Client config (auto-discovery):**

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-server.com/mcp"
    }
  }
}
```

Client fetches metadata, sees your server as issuer, does OAuth flow through your server.

---

## Deployment Configuration

### Environment Variables (Recommended)

```bash
# OAuth provider
export OAUTH_PROVIDER=okta
export OAUTH_ISSUER=https://company.okta.com
export OAUTH_AUDIENCE=api://my-server

# Proxy mode (if needed)
export OAUTH_CLIENT_ID=your-client-id
export OAUTH_CLIENT_SECRET=your-client-secret
export OAUTH_SERVER_URL=https://your-server.com
export OAUTH_REDIRECT_URIS=https://your-server.com/oauth/callback

# HMAC (if using)
export JWT_SECRET=your-32-byte-secret
```

### Kubernetes (Helm)

```yaml
# values.yaml
oauth:
  enabled: true
  mode: native  # or proxy
  provider: okta
  redirectURIs: ""  # For proxy mode

  oidc:
    issuer: https://company.okta.com
    audience: api://my-server
    clientId: ""        # For proxy mode
    clientSecret: ""    # For proxy mode (stored in Secret)
```

### Docker Compose

```yaml
services:
  mcp-server:
    image: your-mcp-server:latest
    environment:
      OAUTH_PROVIDER: okta
      OAUTH_ISSUER: https://company.okta.com
      OAUTH_AUDIENCE: api://my-server
    env_file:
      - .env.secrets  # Contains OAUTH_CLIENT_SECRET, JWT_SECRET
```

---

# Testing Your Setup

## 1. Verify OAuth Endpoints

```bash
# Check OAuth discovery
curl https://your-server.com/.well-known/oauth-authorization-server | jq

# Expected output:
# {
#   "issuer": "https://your-company.okta.com",
#   "authorization_endpoint": "https://your-company.okta.com/oauth2/v1/authorize",
#   ...
# }
```

## 2. Test 401 Handling

```bash
# Request without token should return 401
curl -v https://your-server.com/mcp

# Expected:
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer realm="OAuth", error="invalid_request", ...
```

## 3. Test with Valid Token

```bash
# Generate test token (see examples/ for token generation)
TOKEN="eyJhbGciOiJIUzI1..."

# Request with token should succeed
curl -X POST https://your-server.com/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Expected:
# {"jsonrpc":"2.0","id":1,"result":{"tools":[...]}}
```

## 4. Test with MCP Client

Add to Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-server.com/mcp"
    }
  }
}
```

Claude Desktop will auto-discover OAuth and guide you through authentication.

---

# Troubleshooting

## Server-Side Issues

### "Authentication required: missing OAuth token"

**Problem:** Tool handler receives request without user in context.

**Solution:** Ensure you're using `CreateHTTPContextFunc()`:

```go
streamable := server.NewStreamableHTTPServer(
    mcpServer,
    server.WithHTTPContextFunc(oauth.CreateHTTPContextFunc()),  // ← Required
)
```

### "Token validation fails"

**Problem:** Valid-looking token rejected.

**Check:**
1. Token's `iss` matches `Config.Issuer`
2. Token's `aud` matches `Config.Audience`
3. Token not expired (`exp` claim)
4. For HMAC: correct `JWTSecret`
5. For OIDC: provider JWKS reachable

Enable debug logging:

```go
cfg.Logger = &oauth.DebugLogger{}  // Logs token validation details
```

## Client-Side Issues

### Client Can't Discover OAuth

**Check:**

```bash
curl https://your-server.com/.well-known/oauth-authorization-server
# Should return 200 with JSON metadata
```

If 404, verify `WithOAuth()` was called and server is running.

### Client Shows "Authentication Required"

**Check:**

1. Client is sending `Authorization: Bearer <token>` header
2. Token is valid (not expired)
3. Token's `iss` and `aud` match server config

**Debug:**
Enable verbose logging in client if available.

### OAuth Flow Fails

**Native mode:**

- Check client can reach OAuth provider directly
- Verify provider's redirect URIs include client's callback

**Proxy mode:**

- Check client can reach your server's /oauth endpoints
- Verify your server's redirect URIs configured in provider

---

## Client Configuration Examples

### Claude Desktop

**Location:**

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Config:**

```json
{
  "mcpServers": {
    "my-oauth-server": {
      "url": "https://mcp-server.example.com/mcp"
    }
  }
}
```

Claude Desktop auto-discovers OAuth via metadata endpoints.

### Cursor / Other MCP Clients

**With auto-discovery:**

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-server.com/mcp"
    }
  }
}
```

**With manual token:**

```json
{
  "mcpServers": {
    "my-server": {
      "url": "https://your-server.com/mcp",
      "headers": {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
      }
    }
  }
}
```

---

## See Also

- [Configuration Guide](CONFIGURATION.md) - Server-side OAuth configuration
- [Provider Guides](providers/) - OAuth provider setup (Okta, Google, Azure, HMAC)
- [Security Guide](SECURITY.md) - Production best practices
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues
- [Examples](../examples/) - Working code examples for both SDKs
