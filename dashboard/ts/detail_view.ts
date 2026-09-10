interface DetailSeller {
  name: string | null;
  handle: string | null;
  phone: string | null;
  account_age: string | null;
  location: string | null;
  last_active: string | null;
  verification: string;
  monthly_activity: number[] | null;
  network_summary: string | null;
}

interface DetailSignal {
  type: string;
  label: string;
  value: string;
  sub: string | null;
}

interface DetailReport {
  report_type: string;
  reported_at: string;
}

interface DetailRiskFactor {
  severity: string;
  name: string;
  description: string;
  contributing_signals: string[];
}

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

interface DetailResponse {
  listing_title: string | null;
  listing_url: string | null;
  risk_score: number;
  risk_level: string;
  fraud_report_count: number;
  platform: string;
  seller: DetailSeller;
  signals: DetailSignal[] | null;
  risk_factors: DetailRiskFactor[] | null;
  reports: DetailReport[] | null;
  social_candidates: PlatformCheckResult[] | null;
}

function buildRiskGauge(score: number, level: string): string {
  const color = riskHex(level);
  const r = 44;
  const circumference = 2 * Math.PI * r;
  const offset = circumference * (1 - score / 100);

  let ticks = "";
  const tickCount = 48;
  for (let i = 0; i < tickCount; i++) {
    const angle = (i * 360) / tickCount;
    const major = i % 6 === 0;
    const len = major ? 6 : 3;
    const outerR = 54;
    const innerR = outerR - len;
    ticks +=
      '<line x1="60" y1="' +
      (60 - outerR) +
      '" x2="60" y2="' +
      (60 - innerR) +
      '" stroke="' +
      (major ? "#3a3a42" : "#24242b") +
      '" stroke-width="1.5" transform="rotate(' +
      angle +
      ' 60 60)" />';
  }

  return (
    '<svg viewBox="0 0 120 120" class="w-full h-full">' +
    ticks +
    '<circle cx="60" cy="60" r="' +
    r +
    '" fill="none" stroke="#1b1b20" stroke-width="9" />' +
    '<circle cx="60" cy="60" r="' +
    r +
    '" fill="none" stroke="' +
    color +
    '" stroke-width="9" stroke-linecap="round" stroke-dasharray="' +
    circumference +
    '" stroke-dashoffset="' +
    offset +
    '" transform="rotate(-90 60 60)" />' +
    '<text x="60" y="57" text-anchor="middle" font-family="JetBrains Mono, monospace" font-weight="700" font-size="30" fill="' +
    color +
    '">' +
    score +
    "</text>" +
    '<text x="60" y="75" text-anchor="middle" font-family="Inter, sans-serif" font-weight="600" font-size="9" fill="#8a8a93" letter-spacing="0.5">/ 100</text>' +
    "</svg>"
  );
}

async function openDetail(analysisId: string): Promise<void> {
  const panel = document.getElementById("detail-view");
  const loading = document.getElementById("detail-loading") as HTMLElement;
  const body = document.getElementById("detail-body") as HTMLElement;
  if (!panel) return;

  panel.classList.remove("hidden");
  loading.classList.remove("hidden");
  loading.textContent = "Loading...";
  body.classList.add("hidden");
  (document.getElementById("detail-title") as HTMLElement).textContent = "";

  try {
    const res = await fetch(API_BASE + "/history/" + analysisId, {
      headers: (window as any).safelyAuth.authHeader(),
    });
    if (res.status === 401) {
      (window as any).safelyAuth.logout();
      return;
    }
    if (!res.ok) {
      loading.textContent = "Could not load this listing.";
      return;
    }
    const data: DetailResponse = await res.json();
    renderDetailBody(data);
    loading.classList.add("hidden");
    body.classList.remove("hidden");
  } catch (e) {
    console.error("Safely: failed to load detail", e);
    loading.textContent = "Could not load this listing.";
  }
}

function renderDetailBody(data: DetailResponse): void {
  const tabBtn = document.querySelector(".detail-tab-btn");
  if (tabBtn && tabBtn.parentElement) {
    tabBtn.parentElement.classList.remove("max-w-md");
    tabBtn.parentElement.classList.add("w-full");
  }

  const intelTab = document.getElementById("detail-tab-content-intel");
  const reportTab = document.getElementById("detail-tab-content-report");
  if (intelTab) intelTab.classList.remove("max-w-2xl");
  if (reportTab) reportTab.classList.remove("max-w-2xl");

  (document.getElementById("detail-title") as HTMLElement).textContent =
    data.listing_title || "Untitled listing";

  const linkEl = document.getElementById("detail-listing-link") as HTMLAnchorElement | null;
  if (linkEl) {
    if (data.listing_url) {
      linkEl.href = data.listing_url;
      linkEl.classList.remove("hidden");
    } else {
      linkEl.classList.add("hidden");
    }
  }

  (document.getElementById("detail-gauge-wrap") as HTMLElement).innerHTML = buildRiskGauge(
    data.risk_score,
    data.risk_level,
  );

  const levelEl = document.getElementById("detail-risk-level") as HTMLElement;
  levelEl.textContent = data.risk_level.charAt(0).toUpperCase() + data.risk_level.slice(1) + " risk";
  levelEl.className = "text-[15px] font-extrabold mt-1 " + verdictTextClass(data.risk_level);

  const reportsChip = document.getElementById("detail-chip-reports") as HTMLElement;
  reportsChip.textContent = String(data.fraud_report_count || 0);
  reportsChip.className =
    "num text-lg font-bold " + (data.fraud_report_count > 0 ? "text-coral" : "text-muted");

  const statusText =
    data.seller.verification === "verified"
      ? "Verified"
      : data.seller.verification === "reported"
        ? "Reported"
        : "Unknown";
  (document.getElementById("detail-chip-status") as HTMLElement).textContent = statusText;
  (document.getElementById("detail-chip-platform") as HTMLElement).textContent = data.platform;
  (document.getElementById("detail-seller-name") as HTMLElement).textContent =
    data.seller.name || "Not found";
  (document.getElementById("detail-seller-username") as HTMLElement).textContent =
    data.seller.handle || "Not found";
  (document.getElementById("detail-seller-phone") as HTMLElement).textContent =
    data.seller.phone || "Not found";
  (document.getElementById("detail-seller-age") as HTMLElement).textContent =
    data.seller.account_age || "Not found";
  (document.getElementById("detail-seller-location") as HTMLElement).textContent =
    data.seller.location || "Not found";
  (document.getElementById("detail-seller-lastactive") as HTMLElement).textContent =
    data.seller.last_active || "Not found";

  const chart = document.getElementById("detail-activity-chart") as HTMLElement;
  const activity = data.seller.monthly_activity || new Array(12).fill(0);
  const max = Math.max.apply(null, activity) || 1;
  chart.innerHTML = activity
    .map((v: number) => {
      const heightPx = Math.max(3, Math.round((v / max) * 44));
      return (
        '<div class="flex-1 flex flex-col items-center justify-end relative">' +
        '<span class="text-[9px] text-ink font-bold num absolute top-0">' +
        v +
        "</span>" +
        '<div class="w-full bg-brand/70 rounded-t" style="height:' +
        heightPx +
        'px"></div></div>'
      );
    })
    .join("");

  (document.getElementById("detail-network-summary") as HTMLElement).textContent =
    data.seller.network_summary || "";

  const signals = data.signals || [];
  const badCount = signals.filter((s) => s.type !== "good" && s.type !== "info").length;
  const summaryEl = document.getElementById("detail-intel-summary") as HTMLElement;

  if (badCount === 0) {
    summaryEl.className = "flex gap-2.5 p-3.5 rounded-xl text-[12px] mb-5 bg-mint/10 text-mint";
    summaryEl.innerHTML =
      "<span>&#9679;</span><span>All " + signals.length + " signals checked. No red flags detected.</span>";
  } else {
    summaryEl.className = "flex gap-2.5 p-3.5 rounded-xl text-[12px] mb-5 bg-amber/10 text-amber";
    summaryEl.innerHTML =
      "<span>&#9679;</span><span>" +
      badCount +
      " of " +
      signals.length +
      " signals need your attention.</span>";
  }

  const priceSignal = signals.find((s) => s.label === "Price analysis");
  const priceSection = document.getElementById("detail-price-vs-market");
  if (priceSection) {
    if (priceSignal) {
      const verdict = priceSignal.value || "unknown";
      const verdictClass = verdict === "normal" ? "text-mint" : "text-amber";
      priceSection.classList.remove("hidden");
      priceSection.innerHTML =
        '<div class="text-[10px] font-extrabold uppercase tracking-wider text-muted mb-1.5">Price vs market</div>' +
        '<div class="bg-surface border border-line rounded-xl p-4">' +
        '<div class="text-[14px] font-bold ' +
        verdictClass +
        '">' +
        verdict.charAt(0).toUpperCase() +
        verdict.slice(1) +
        "</div>" +
        '<div class="text-[12px] text-muted mt-1.5">' +
        (priceSignal.sub || "") +
        "</div></div>";
    } else {
      priceSection.classList.add("hidden");
    }
  }

  const signalsList = document.getElementById("detail-signals-list") as HTMLElement;
  signalsList.innerHTML = signals
    .map(
      (s) =>
        '<div class="bg-surface border border-line rounded-xl p-4 mb-2.5 last:mb-0">' +
        '<div class="flex justify-between items-baseline gap-3">' +
        '<div class="font-semibold text-[13px]">' +
        s.label +
        "</div>" +
        '<div class="text-[13px] font-bold whitespace-nowrap ' +
        signalTextClass(s.type) +
        '">' +
        s.value +
        "</div></div>" +
        '<div class="text-[12px] text-muted mt-1.5">' +
        (s.sub || "") +
        "</div></div>",
    )
    .join("");

  const socialPresenceEl = document.getElementById("detail-social-presence");
  if (socialPresenceEl) {
    socialPresenceEl.innerHTML = buildSocialPresenceSection(data.social_candidates || []);
  }

  const riskFactorsSection = document.getElementById("detail-risk-factors");
  const riskFactors = data.risk_factors || [];
  if (riskFactorsSection) {
    if (riskFactors.length > 0) {
      const severityColors: Record<string, string> = {
        hard: "text-coral",
        compound: "text-amber",
        soft: "text-muted",
      };
      const severityLabels: Record<string, string> = {
        hard: "Confirmed",
        compound: "Pattern match",
        soft: "Worth noting",
      };
      const capitalizeFirst = (str: string): string =>
        str ? str.charAt(0).toUpperCase() + str.slice(1) : str;

      riskFactorsSection.classList.remove("hidden");
      riskFactorsSection.innerHTML =
        '<div class="text-[10px] font-extrabold uppercase tracking-wider text-muted mb-2">Risk factors</div>' +
        riskFactors
          .map((f) => {
            const colorClass = severityColors[f.severity] || "text-muted";
            const severityLabel = severityLabels[f.severity] || f.severity;
            return (
              '<div class="bg-surface border border-line rounded-xl p-4 mb-2.5 last:mb-0">' +
              '<div class="flex justify-between items-baseline gap-3">' +
              '<div class="font-semibold text-[13px]">' +
              capitalizeFirst(f.name.replace(/_/g, " ")) +
              "</div>" +
              '<div class="text-[13px] font-bold whitespace-nowrap ' +
              colorClass +
              '">' +
              severityLabel +
              "</div></div>" +
              '<div class="text-[12px] text-muted mt-1.5">' +
              f.description +
              "</div></div>"
            );
          })
          .join("");
    } else {
      riskFactorsSection.classList.add("hidden");
      riskFactorsSection.innerHTML = "";
    }
  }

  const filedBlock = document.getElementById("detail-report-filed") as HTMLElement;
  const emptyBlock = document.getElementById("detail-report-empty") as HTMLElement;
  const reports = data.reports || [];

  if (reports.length > 0) {
    filedBlock.classList.remove("hidden");
    emptyBlock.classList.add("hidden");
    filedBlock.innerHTML = reports
      .map(
        (r) =>
          '<div class="bg-surface border border-line rounded-xl p-4 mb-2.5 last:mb-0">' +
          '<div class="text-[10px] font-extrabold uppercase tracking-wider text-muted mb-1.5">Report reason</div>' +
          '<div class="text-[14px] font-semibold">' +
          r.report_type +
          "</div>" +
          '<div class="text-[12px] text-muted mt-2">Submitted ' +
          formatDate(r.reported_at) +
          "</div>" +
          "</div>",
      )
      .join("");
  } else {
    filedBlock.classList.add("hidden");
    filedBlock.innerHTML = "";
    emptyBlock.classList.remove("hidden");
  }

  switchDetailTab("risk");
}

const PLATFORM_ORDER = [
  "Facebook", "LinkedIn", "TikTok", "Instagram", "Reddit", "Trustpilot",
  "Reviews", "Contact (Facebook)", "Contact (LinkedIn)", "Contact (Web)",
];

function buildSocialPresenceSection(results: PlatformCheckResult[]): string {
  if (!results || results.length === 0) return "";

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
    .map((platform, index) => {
      const links = grouped[platform];
      const isLast = index === order.length - 1;
      const body =
        links.length === 0
          ? '<div class="text-[12px] text-muted py-1">Not found</div>'
          : links
              .map(
                (link) =>
                  '<div class="flex items-start gap-2 py-1.5">' +
                  '<span class="text-muted flex-shrink-0 mt-0.5">&#8226;</span>' +
                  '<a href="' +
                  escapeHtml(link.url) +
                  '" target="_blank" rel="noopener noreferrer" class="text-[12px] text-ink hover:text-brand flex-1 min-w-0 no-underline">' +
                  escapeHtml(link.title) +
                  "</a></div>",
              )
              .join("");
      return (
        '<div class="py-2.5' +
        (isLast ? "" : " border-b border-line") +
        '">' +
        '<div class="text-[10px] font-extrabold uppercase tracking-wider text-muted mb-1.5">' +
        escapeHtml(platform) +
        "</div>" +
        body +
        "</div>"
      );
    })
    .join("");

  return (
    '<div class="text-[10px] font-extrabold uppercase tracking-wider text-muted mb-2 mt-5">Social presence check</div>' +
    '<div class="bg-surface border border-line rounded-xl p-4 mb-5">' +
    groupsHTML +
    "</div>"
  );
}

function escapeHtml(str: string): string {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function switchDetailTab(tab: string): void {
  ["risk", "intel", "report"].forEach((name) => {
    const content = document.getElementById("detail-tab-content-" + name);
    if (content) content.classList.toggle("hidden", name !== tab);
  });
  document.querySelectorAll<HTMLElement>(".detail-tab-btn").forEach((btn) => {
    const active = btn.dataset.detailTab === tab;
    btn.classList.toggle("bg-surface3", active);
    btn.classList.toggle("text-ink", active);
  });
}

function closeDetailPanel(): void {
  const panel = document.getElementById("detail-view");
  if (panel) panel.classList.add("hidden");
}
