import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { fakeChrome } from "./setup-chrome";
function formatPlatformName(platform: string | null | undefined): string {
  if (!platform) return "Not found";
  const names: Record<string, string> = {
    olx: "OLX",
    b2brazil: "B2Brazil",
  };
  return names[platform] || platform;
}
import "../ts/core/api";

const api = (window as any).__safelyAPI;

let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  fakeChrome.storage.local.get = vi.fn().mockResolvedValue({});
  (globalThis as any).fetch = vi.fn();
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  consoleErrorSpy.mockRestore();
});

describe("analyze", () => {
  it("returns the parsed response on success", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ risk_score: 42, fraud_report_count: 0 }),
    });

    const result = await api.analyze({} as any);
    expect(result).toEqual({ risk_score: 42, fraud_report_count: 0 });
  });

  it("attaches the real Authorization header when a session token exists", async () => {
    fakeChrome.storage.local.get = vi.fn().mockResolvedValue({
      safely_session_token: "real-token-123",
    });
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ risk_score: 10 }),
    });

    await api.analyze({} as any);

    const callArgs = (globalThis as any).fetch.mock.calls[0];
    expect(callArgs[1].headers.Authorization).toBe("Bearer real-token-123");
  });

  it("does not attach an Authorization header when no token exists", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ risk_score: 10 }),
    });

    await api.analyze({} as any);

    const callArgs = (globalThis as any).fetch.mock.calls[0];
    expect(callArgs[1].headers.Authorization).toBeUndefined();
  });

  it("returns a rate_limited error with the real retry time on a 429 response", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: false,
      status: 429,
      text: async () => "error: RATE_LIMITED:45",
    });

    const result = await api.analyze({} as any);
    expect(result).toEqual({ error: "rate_limited", retryAfterSeconds: 45 });
  });

  it("returns an unauthorized error on a 401 response", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "error: unauthorized",
    });

    const result = await api.analyze({} as any);
    expect(result).toEqual({ error: "unauthorized" });
  });

  it("returns null for any other, unrecognized failure", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => "error: something else broke",
    });

    const result = await api.analyze({} as any);
    expect(result).toBeNull();
  });

  it("returns null when the fetch call itself throws (e.g. network failure)", async () => {
    (globalThis as any).fetch.mockRejectedValue(new Error("network down"));

    const result = await api.analyze({} as any);
    expect(result).toBeNull();
  });
});

describe("submitReport", () => {
  it("returns the parsed response on success", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ success: true }),
    });

    const result = await api.submitReport({} as any);
    expect(result).toEqual({ success: true });
  });

  it("returns an unauthorized error on a 401 response", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "error: unauthorized",
    });

    const result = await api.submitReport({} as any);
    expect(result).toEqual({ error: "unauthorized" });
  });

  it("returns null for any other failure", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => "error: server broke",
    });

    const result = await api.submitReport({} as any);
    expect(result).toBeNull();
  });

  it("returns null when the fetch call itself throws", async () => {
    (globalThis as any).fetch.mockRejectedValue(new Error("network down"));

    const result = await api.submitReport({} as any);
    expect(result).toBeNull();
  });
});

describe("checkSubscriptionStatus", () => {
  it("returns the real status string on success", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      json: async () => ({ status: "active" }),
    });
    const result = await api.checkSubscriptionStatus();
    expect(result).toBe("active");
  });

  it("returns null when the response has no status field at all", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      json: async () => ({}),
    });
    const result = await api.checkSubscriptionStatus();
    expect(result).toBeNull();
  });

  it("returns null when the response is not ok", async () => {
    (globalThis as any).fetch.mockResolvedValue({
      ok: false,
      json: async () => ({ status: "active" }),
    });
    const result = await api.checkSubscriptionStatus();
    expect(result).toBeNull();
  });

  it("returns null when the fetch call itself throws", async () => {
    (globalThis as any).fetch.mockRejectedValue(new Error("network down"));
    const result = await api.checkSubscriptionStatus();
    expect(result).toBeNull();
  });
});

describe("submitOutcome", () => {
  it("returns true on a genuine, successful response", async () => {
    (globalThis as any).fetch.mockResolvedValue({ ok: true });
    const result = await api.submitOutcome("analysis-123", "proceeded");
    expect(result).toBe(true);
  });

  it("returns false when the response is not ok", async () => {
    (globalThis as any).fetch.mockResolvedValue({ ok: false });
    const result = await api.submitOutcome("analysis-123", "aborted");
    expect(result).toBe(false);
  });

  it("returns false when the fetch call itself throws", async () => {
    (globalThis as any).fetch.mockRejectedValue(new Error("network down"));
    const result = await api.submitOutcome("analysis-123", "proceeded");
    expect(result).toBe(false);
  });

  it("sends the real analysis_id and action in the request body", async () => {
    (globalThis as any).fetch.mockResolvedValue({ ok: true });
    await api.submitOutcome("real-analysis-id-456", "aborted");

    const callArgs = (globalThis as any).fetch.mock.calls[0];
    const sentBody = JSON.parse(callArgs[1].body);
    expect(sentBody).toEqual({ analysis_id: "real-analysis-id-456", action: "aborted" });
  });

  it("attaches the real Authorization header when a session token exists", async () => {
    fakeChrome.storage.local.get = vi.fn().mockResolvedValue({
      safely_session_token: "real-token-789",
    });
    (globalThis as any).fetch.mockResolvedValue({ ok: true });
    await api.submitOutcome("analysis-123", "proceeded");

    const callArgs = (globalThis as any).fetch.mock.calls[0];
    expect(callArgs[1].headers.Authorization).toBe("Bearer real-token-789");
  });
});

describe("formatPlatformName", () => {
  it("returns the real, correct display name for olx", () => {
    expect(formatPlatformName("olx")).toBe("OLX");
  });

  it("returns the real, correct display name for b2brazil", () => {
    expect(formatPlatformName("b2brazil")).toBe("B2Brazil");
  });

  it("returns the raw platform string unchanged for an unrecognized platform", () => {
    expect(formatPlatformName("alibaba")).toBe("alibaba");
  });

  it("returns 'Not found' for null", () => {
    expect(formatPlatformName(null)).toBe("Not found");
  });

  it("returns 'Not found' for undefined", () => {
    expect(formatPlatformName(undefined)).toBe("Not found");
  });

  it("returns 'Not found' for an empty string", () => {
    expect(formatPlatformName("")).toBe("Not found");
  });
});

describe("fetchAnalysis", () => {
  function setupScraperMocks(overrides: Partial<Record<string, any>> = {}) {
    (window as any).__safelyScrapers = {
      loadProtectedDomains: vi.fn().mockResolvedValue(undefined),
      detectPlatform: vi.fn().mockReturnValue("olx"),
      isListingPage: vi.fn().mockReturnValue(true),
      requiresClientSideScraping: vi.fn().mockReturnValue(false),
      checkDomain: vi.fn().mockReturnValue(null),
      ...overrides,
    };
  }

  it("dispatches safely-analysis-finished immediately for an unknown platform", async () => {
    setupScraperMocks({ detectPlatform: vi.fn().mockReturnValue("unknown") });
    const dispatchSpy = vi.spyOn(window, "dispatchEvent");

    await api.fetchAnalysis();

    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({ type: "safely-analysis-finished" }),
    );
    expect((globalThis as any).fetch).not.toHaveBeenCalled();
  });

  it("dispatches safely-analysis-finished immediately when not on a real listing page", async () => {
    setupScraperMocks({ isListingPage: vi.fn().mockReturnValue(false) });
    const dispatchSpy = vi.spyOn(window, "dispatchEvent");

    await api.fetchAnalysis();

    expect(dispatchSpy).toHaveBeenCalledWith(
      expect.objectContaining({ type: "safely-analysis-finished" }),
    );
    expect((globalThis as any).fetch).not.toHaveBeenCalled();
  });

  it("correctly populates __safelyData on a genuine, successful analysis", async () => {
    setupScraperMocks();
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          analysis_id: "real-id-123",
          risk_score: 55,
          fraud_report_count: 2,
          risk_factors: [],
          seller: {
            id: "seller-1",
            name: "Real Seller",
            platform: "olx",
            platform_id: "p1",
            handle: null,
            phone: null,
            account_age: "2 years",
            verification: "unknown",
            location: "Lahore",
            last_active: "Today",
            network_summary: "Clean record.",
            monthly_activity: [0, 1, 0],
          },
          signals: [{ label: "Price analysis", sub: "normal", value: "normal", type: "good" }],
        }),
    });

    await api.fetchAnalysis();

    const pageData = (window as any).__safelyData;
    expect(pageData.analysisId).toBe("real-id-123");
    expect(pageData.riskScore).toBe(55);
    expect(pageData.seller.name).toBe("Real Seller");
    expect(pageData.seller.platform).toBe("OLX");
    expect(pageData.signals).toHaveLength(1);
  });

  it("dispatches an error event with the real error detail when analyze() fails", async () => {
    setupScraperMocks();
    (globalThis as any).fetch.mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => "error: unauthorized",
    });
    const dispatchSpy = vi.spyOn(window, "dispatchEvent");

    await api.fetchAnalysis();

    const finishedEvent = dispatchSpy.mock.calls.find(
      (call) => (call[0] as CustomEvent).type === "safely-analysis-finished",
    );
    expect(finishedEvent).toBeDefined();
    expect((finishedEvent![0] as CustomEvent).detail.error).toBe("unauthorized");
  });

  it("waits before scraping when the platform requires client-side scraping", async () => {
    vi.useFakeTimers();
    setupScraperMocks({ requiresClientSideScraping: vi.fn().mockReturnValue(true) });
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          seller: { id: "s1", monthly_activity: [] },
          signals: [],
        }),
    });

    const promise = api.fetchAnalysis();
    await vi.advanceTimersByTimeAsync(1500);
    await promise;

    vi.useRealTimers();
  });

  it("correctly reads and includes real domain check data in the payload", async () => {
    setupScraperMocks({
      checkDomain: vi.fn().mockReturnValue({
        status: "suspicious",
        realName: "OLX",
        realDomain: "olx.com.pk",
        currentDomain: "0lx.com.pk",
      }),
    });
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ seller: { id: "s1", monthly_activity: [] }, signals: [] }),
    });

    await api.fetchAnalysis();

    const callArgs = (globalThis as any).fetch.mock.calls[0];
    const sentBody = JSON.parse(callArgs[1].body);
    expect(sentBody.domain_check_status).toBe("suspicious");
    expect(sentBody.domain_check_real_domain).toBe("olx.com.pk");
  });
});
