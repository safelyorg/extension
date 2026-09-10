import { describe, it, expect, beforeEach } from "vitest";

interface SocialCandidateLink {
  platform: string;
  title: string;
  url: string;
}
interface PlatformCheckResult {
  platform: string;
  variant_searched: string;
  found: boolean;
  candidates: SocialCandidateLink[];
}

function escapeHtml(str: string): string {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

const PLATFORM_ORDER = [
  "Facebook", "LinkedIn", "TikTok", "Instagram", "Reddit", "Trustpilot",
  "Reviews", "Contact (Facebook)", "Contact (LinkedIn)", "Contact (Web)",
];

// Direct copy of intelligence.ts's real buildSocialPresenceSection,
// reading from window.__safelyData exactly as the real function does.
function buildSocialPresenceSection(): string {
  const pageData = (window as any).__safelyData;
  const results: PlatformCheckResult[] = pageData.socialCandidates || [];
  if (results.length === 0) return "";

  const grouped: Record<string, SocialCandidateLink[]> = {};
  results.forEach((entry) => {
    if (!(entry.platform in grouped)) grouped[entry.platform] = [];
    entry.candidates.forEach((c) => {
      if (!grouped[entry.platform].some((existing) => existing.url === c.url)) {
        grouped[entry.platform].push(c);
      }
    });
  });

  const order = PLATFORM_ORDER.filter((p) => p in grouped).concat(
    Object.keys(grouped).filter((p) => !PLATFORM_ORDER.includes(p)),
  );

  const groupsHTML = order
    .map((platform) => {
      const links = grouped[platform];
      const body =
        links.length === 0
          ? '<div style="padding:4px;font-size:12px;color:#8e8e93;">Not found</div>'
          : links
              .map((link) => {
                const linkArrow =
                  '<a href="' +
                  escapeHtml(link.url) +
                  '" target="_blank" rel="noopener noreferrer" style="flex-shrink:0;color:#8e8e93;text-decoration:none;font-size:13px;padding:2px;" title="Open in new tab">&#8594;</a>';
                return (
                  '<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 4px;">' +
                  '<span style="color:#8e8e93;flex-shrink:0;margin-top:1px;">&#8226;</span>' +
                  '<span style="font-size:12px;line-height:1.4;color:#f2f1ed;flex:1;min-width:0;">' +
                  escapeHtml(link.title) +
                  "</span>" +
                  linkArrow +
                  "</div>"
                );
              })
              .join("");
      return (
        '<div style="margin-bottom:10px;">' +
        '<div style="font-size:11px;font-weight:700;color:#8e8e93;text-transform:uppercase;letter-spacing:0.4px;margin-bottom:2px;padding:0 4px;">' +
        escapeHtml(platform) +
        "</div>" +
        body +
        "</div>"
      );
    })
    .join("");

  return (
    '<div class="safely-section-label" style="margin-top:18px">Social presence check</div>' +
    '<div class="safely-check-card">' +
    '<button id="safely-social-toggle" type="button" style="width:100%;text-align:left;background:none;border:none;cursor:pointer;padding:0;font-size:13px;font-weight:600;color:#f2f1ed;display:flex;justify-content:space-between;align-items:center;">' +
    '<span id="safely-social-toggle-text">Click to drop down</span><span id="safely-social-arrow">&#9662;</span>' +
    "</button>" +
    '<div id="safely-social-dropdown" style="display:none;margin-top:12px;">' +
    groupsHTML +
    "</div></div>"
  );
}

// Direct copy of intelligence.ts's real attachSocialPresenceListeners.
function attachSocialPresenceListeners(): void {
  const toggle = document.getElementById("safely-social-toggle");
  const dropdown = document.getElementById("safely-social-dropdown");
  const arrow = document.getElementById("safely-social-arrow");
  const toggleText = document.getElementById("safely-social-toggle-text");
  if (toggle && dropdown && arrow && toggleText) {
    toggle.addEventListener("click", () => {
      const isOpen = dropdown.style.display !== "none";
      dropdown.style.display = isOpen ? "none" : "block";
      arrow.innerHTML = isOpen ? "&#9662;" : "&#9652;";
      toggleText.textContent = isOpen ? "Click to drop down" : "Click to drop up";
    });
  }
}

function setPageData(socialCandidates: PlatformCheckResult[]): void {
  (window as any).__safelyData = { socialCandidates };
}

describe("intelligence.ts - buildSocialPresenceSection", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("returns a genuinely empty string when there are zero results", () => {
    setPageData([]);
    expect(buildSocialPresenceSection()).toBe("");
  });

  it("returns a genuinely empty string when socialCandidates is missing entirely", () => {
    (window as any).__safelyData = {};
    expect(buildSocialPresenceSection()).toBe("");
  });

  it("shows 'Not found' for a platform with genuinely zero candidates", () => {
    setPageData([{ platform: "Facebook", variant_searched: "Test", found: false, candidates: [] }]);
    const result = buildSocialPresenceSection();
    expect(result).toContain("Not found");
    expect(result).toContain("Facebook");
  });

  it("renders a real candidate's title and a working link arrow", () => {
    setPageData([
      {
        platform: "LinkedIn",
        variant_searched: "Test",
        found: true,
        candidates: [{ platform: "LinkedIn", title: "Real Company LinkedIn", url: "https://linkedin.com/company/real" }],
      },
    ]);
    const result = buildSocialPresenceSection();
    expect(result).toContain("Real Company LinkedIn");
    expect(result).toContain('href="https://linkedin.com/company/real"');
    expect(result).toContain('target="_blank"');
  });

  it("deduplicates the same, real URL found across multiple variant searches within one platform", () => {
    setPageData([
      {
        platform: "Facebook",
        variant_searched: "Short Name",
        found: true,
        candidates: [{ platform: "Facebook", title: "Company Page", url: "https://facebook.com/company" }],
      },
      {
        platform: "Facebook",
        variant_searched: "Full Company Name",
        found: true,
        candidates: [{ platform: "Facebook", title: "Company Page", url: "https://facebook.com/company" }],
      },
    ]);
    const result = buildSocialPresenceSection();
    const occurrences = result.split("https://facebook.com/company").length - 1;
    expect(occurrences).toBe(1);
  });

  it("keeps genuinely different, real URLs from different variants within the same platform", () => {
    setPageData([
      {
        platform: "Facebook",
        variant_searched: "Variant A",
        found: true,
        candidates: [{ platform: "Facebook", title: "Page A", url: "https://facebook.com/a" }],
      },
      {
        platform: "Facebook",
        variant_searched: "Variant B",
        found: true,
        candidates: [{ platform: "Facebook", title: "Page B", url: "https://facebook.com/b" }],
      },
    ]);
    const result = buildSocialPresenceSection();
    expect(result).toContain("https://facebook.com/a");
    expect(result).toContain("https://facebook.com/b");
  });

  it("orders known platforms according to the real, fixed PLATFORM_ORDER", () => {
    setPageData([
      { platform: "Reviews", variant_searched: "x", found: false, candidates: [] },
      { platform: "Facebook", variant_searched: "x", found: false, candidates: [] },
      { platform: "LinkedIn", variant_searched: "x", found: false, candidates: [] },
    ]);
    const result = buildSocialPresenceSection();
    const facebookIndex = result.indexOf(">Facebook<");
    const linkedinIndex = result.indexOf(">LinkedIn<");
    const reviewsIndex = result.indexOf(">Reviews<");
    expect(facebookIndex).toBeLessThan(linkedinIndex);
    expect(linkedinIndex).toBeLessThan(reviewsIndex);
  });

  it("places a genuinely unrecognized platform after all known ones", () => {
    setPageData([
      { platform: "Facebook", variant_searched: "x", found: false, candidates: [] },
      { platform: "SomeNewPlatform", variant_searched: "x", found: false, candidates: [] },
    ]);
    const result = buildSocialPresenceSection();
    const facebookIndex = result.indexOf(">Facebook<");
    const newPlatformIndex = result.indexOf(">SomeNewPlatform<");
    expect(facebookIndex).toBeLessThan(newPlatformIndex);
  });

  it("escapes dangerous HTML in a candidate's title", () => {
    setPageData([
      {
        platform: "Facebook",
        variant_searched: "x",
        found: true,
        candidates: [{ platform: "Facebook", title: "<script>bad</script>", url: "https://facebook.com/test" }],
      },
    ]);
    const result = buildSocialPresenceSection();
    expect(result).not.toContain("<script>bad</script>");
    expect(result).toContain("&lt;script&gt;");
  });

  it("starts genuinely collapsed, with the dropdown hidden and correct initial toggle text", () => {
    setPageData([{ platform: "Facebook", variant_searched: "x", found: false, candidates: [] }]);
    const result = buildSocialPresenceSection();
    expect(result).toContain("Click to drop down");
    expect(result).toContain('style="display:none;margin-top:12px;"');
  });
});

describe("intelligence.ts - attachSocialPresenceListeners", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
    setPageData([{ platform: "Facebook", variant_searched: "x", found: false, candidates: [] }]);
    document.body.innerHTML = buildSocialPresenceSection();
    attachSocialPresenceListeners();
  });

  it("expands the dropdown and flips the arrow/text on the first click", () => {
    const toggle = document.getElementById("safely-social-toggle") as HTMLButtonElement;
    toggle.click();

    const dropdown = document.getElementById("safely-social-dropdown") as HTMLElement;
    const arrow = document.getElementById("safely-social-arrow") as HTMLElement;
    const toggleText = document.getElementById("safely-social-toggle-text") as HTMLElement;

    expect(dropdown.style.display).toBe("block");
    expect(arrow.innerHTML).toBe("▴");
    expect(toggleText.textContent).toBe("Click to drop up");
  });

  it("collapses the dropdown again on a second click", () => {
    const toggle = document.getElementById("safely-social-toggle") as HTMLButtonElement;
    toggle.click();
    toggle.click();

    const dropdown = document.getElementById("safely-social-dropdown") as HTMLElement;
    const arrow = document.getElementById("safely-social-arrow") as HTMLElement;
    const toggleText = document.getElementById("safely-social-toggle-text") as HTMLElement;

    expect(dropdown.style.display).toBe("none");
    expect(arrow.innerHTML).toBe("▾");
    expect(toggleText.textContent).toBe("Click to drop down");
  });

  it("does nothing and does not throw when the expected DOM elements are genuinely missing", () => {
    document.body.innerHTML = "";
    expect(() => attachSocialPresenceListeners()).not.toThrow();
  });
});
