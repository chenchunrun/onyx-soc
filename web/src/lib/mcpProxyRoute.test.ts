const ORIGINAL_ENV = process.env;

const makeRequest = (headers: Record<string, string>) =>
  ({
    method: "GET",
    headers: new Headers(headers),
    nextUrl: new URL("http://localhost:3000/mcp/v1/status?foo=bar"),
    signal: new AbortController().signal,
    body: null,
  }) as any;

const makeContext = () =>
  ({
    params: Promise.resolve({ path: ["v1", "status"] }),
  }) as any;

describe("MCP proxy route header forwarding", () => {
  beforeEach(() => {
    jest.resetModules();
    process.env = { ...ORIGINAL_ENV };
    process.env.NODE_ENV = "development";
    process.env.OVERRIDE_API_PRODUCTION = "false";
    process.env.MCP_INTERNAL_URL = "http://127.0.0.1:8090";
    delete process.env.MCP_PROXY_FORWARD_AUTHORIZATION;

    global.fetch = jest.fn().mockResolvedValue(
      new Response("ok", { status: 200 })
    ) as jest.Mock;
  });

  afterAll(() => {
    process.env = ORIGINAL_ENV;
  });

  it("does not forward cookie/auth headers by default", async () => {
    const route = await import("@/app/mcp/[[...path]]/route");

    await route.GET(
      makeRequest({
        authorization: "Bearer secret-token",
        cookie: "sessionid=abc",
        "content-type": "application/json",
        "x-request-id": "req-1",
        "x-onyx-trace": "trace-123",
      }),
      makeContext()
    );

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [targetUrl, fetchOptions] = (global.fetch as jest.Mock).mock.calls[0];
    expect(targetUrl).toBe("http://127.0.0.1:8090/v1/status?foo=bar");

    const forwardedHeaders = Object.fromEntries(
      (fetchOptions.headers as Headers).entries()
    );
    expect(forwardedHeaders["content-type"]).toBe("application/json");
    expect(forwardedHeaders["x-request-id"]).toBe("req-1");
    expect(forwardedHeaders["x-onyx-trace"]).toBe("trace-123");
    expect(forwardedHeaders.authorization).toBeUndefined();
    expect(forwardedHeaders.cookie).toBeUndefined();
  });

  it("forwards authorization when explicitly enabled", async () => {
    process.env.MCP_PROXY_FORWARD_AUTHORIZATION = "true";
    const route = await import("@/app/mcp/[[...path]]/route");

    await route.GET(
      makeRequest({
        authorization: "Bearer secret-token",
        "content-type": "application/json",
      }),
      makeContext()
    );

    expect(global.fetch).toHaveBeenCalledTimes(1);
    const [, fetchOptions] = (global.fetch as jest.Mock).mock.calls[0];
    const forwardedHeaders = Object.fromEntries(
      (fetchOptions.headers as Headers).entries()
    );
    expect(forwardedHeaders.authorization).toBe("Bearer secret-token");
  });
});
