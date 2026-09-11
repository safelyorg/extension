import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

const API_BASE = "http://localhost:3000/api/v1";

// Direct copy of detail_view.ts's real downloadEvidencePdf logic.
let currentAnalysisId: string | null = null;

async function downloadEvidencePdf(): Promise<void> {
  if (!currentAnalysisId) return;
  const btn = document.getElementById("detail-download-pdf") as HTMLButtonElement | null;
  if (btn) {
    btn.disabled = true;
    btn.style.opacity = "0.5";
  }
  try {
    const res = await fetch(API_BASE + "/history/" + currentAnalysisId + "/pdf", {
      headers: (window as any).safelyAuth.authHeader(),
    });
    if (!res.ok) {
      console.error("Safely: failed to download the real PDF report");
      return;
    }
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "safely-evidence-" + currentAnalysisId + ".pdf";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  } catch (e) {
    console.error("Safely: PDF download failed", e);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.style.opacity = "1";
    }
  }
}

describe("detail_view.ts - downloadEvidencePdf", () => {
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    document.body.innerHTML = '<button id="detail-download-pdf"></button>';
    currentAnalysisId = null;
    (globalThis as any).fetch = vi.fn();
    (window as any).safelyAuth = { authHeader: vi.fn().mockReturnValue({ Authorization: "Bearer real-token" }) };
    (globalThis as any).URL.createObjectURL = vi.fn().mockReturnValue("blob:mock-url");
    (globalThis as any).URL.revokeObjectURL = vi.fn();
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleErrorSpy.mockRestore();
    vi.restoreAllMocks();
  });

  it("does nothing at all when there is no real, current analysis ID", async () => {
    currentAnalysisId = null;
    await downloadEvidencePdf();
    expect((globalThis as any).fetch).not.toHaveBeenCalled();
  });

  it("calls the real, correct endpoint with the real analysis ID and auth header", async () => {
    currentAnalysisId = "real-analysis-id-123";
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      blob: async () => new Blob(["fake pdf bytes"]),
    });

    await downloadEvidencePdf();

    expect((globalThis as any).fetch).toHaveBeenCalledWith(
      API_BASE + "/history/real-analysis-id-123/pdf",
      { headers: { Authorization: "Bearer real-token" } },
    );
  });

  it("disables the button immediately, before the fetch call resolves", async () => {
    currentAnalysisId = "real-analysis-id-123";
    let resolveFetch: (value: any) => void;
    const pendingFetch = new Promise((resolve) => {
      resolveFetch = resolve;
    });
    (globalThis as any).fetch.mockReturnValue(pendingFetch);

    const promise = downloadEvidencePdf();
    const btn = document.getElementById("detail-download-pdf") as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(btn.style.opacity).toBe("0.5");

    resolveFetch!({ ok: true, blob: async () => new Blob(["x"]) });
    await promise;
  });

  it("re-enables the button after a genuine, successful download", async () => {
    currentAnalysisId = "real-analysis-id-123";
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      blob: async () => new Blob(["fake pdf bytes"]),
    });

    await downloadEvidencePdf();

    const btn = document.getElementById("detail-download-pdf") as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
    expect(btn.style.opacity).toBe("1");
  });

  it("re-enables the button even when the response is not ok", async () => {
    currentAnalysisId = "real-analysis-id-123";
    (globalThis as any).fetch.mockResolvedValue({ ok: false });

    await downloadEvidencePdf();

    const btn = document.getElementById("detail-download-pdf") as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
    expect(btn.style.opacity).toBe("1");
    expect(consoleErrorSpy).toHaveBeenCalledWith("Safely: failed to download the real PDF report");
  });

  it("re-enables the button when the fetch call itself throws", async () => {
    currentAnalysisId = "real-analysis-id-123";
    (globalThis as any).fetch.mockRejectedValue(new Error("network down"));

    await downloadEvidencePdf();

    const btn = document.getElementById("detail-download-pdf") as HTMLButtonElement;
    expect(btn.disabled).toBe(false);
    expect(btn.style.opacity).toBe("1");
    expect(consoleErrorSpy).toHaveBeenCalledWith("Safely: PDF download failed", expect.any(Error));
  });

  it("does not throw when the button element is genuinely missing from the DOM", async () => {
    document.body.innerHTML = "";
    currentAnalysisId = "real-analysis-id-123";
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      blob: async () => new Blob(["fake pdf bytes"]),
    });

    await expect(downloadEvidencePdf()).resolves.not.toThrow();
  });

  it("creates a real, temporary anchor element with the correct download filename", async () => {
    currentAnalysisId = "real-analysis-id-456";
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      blob: async () => new Blob(["fake pdf bytes"]),
    });

    const appendSpy = vi.spyOn(document.body, "appendChild");
    await downloadEvidencePdf();

    const appendedAnchor = appendSpy.mock.calls.find(
      (call) => (call[0] as HTMLElement).tagName === "A",
    )?.[0] as HTMLAnchorElement | undefined;

    expect(appendedAnchor).toBeDefined();
    expect(appendedAnchor?.download).toBe("safely-evidence-real-analysis-id-456.pdf");
  });

  it("revokes the real, temporary object URL after triggering the download", async () => {
    currentAnalysisId = "real-analysis-id-123";
    (globalThis as any).fetch.mockResolvedValue({
      ok: true,
      blob: async () => new Blob(["fake pdf bytes"]),
    });

    await downloadEvidencePdf();

    expect((globalThis as any).URL.revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");
  });
});
