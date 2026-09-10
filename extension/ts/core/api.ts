interface AnalyzePayload {
  platform: string;
  listing_url: string;
  seller_id: string | null;
  listing_id: string | null;
  title: string | null;
  price: number | null;
  description: string | null;
  category: string | null;
  image_urls: string[] | null;
  posted_date: string | null;
  platform_id: string | null;
  seller_name: string | null;
  seller_handle: string | null;
  seller_phone: string | null;
  seller_profile_url: string | null;
  seller_join_date: string | null;
  seller_location: string | null;
  seller_last_active: string | null;
  seller_website: string | null;
  seller_verified: boolean;
  seller_rating: number | null;
  seller_total_products: number | null;
  domain_check_status: string | null;
  domain_check_real_name: string | null;
  domain_check_real_domain: string | null;
  domain_check_current_domain: string | null;
  domain_check_current_html: string | null;
  domain_check_real_html: string | null;
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
interface AnalyzeResponse {
  error?: string;
  retryAfterSeconds?: number | null;
  analysis_id: string;
  risk_score: number;
  fraud_report_count: number;
  risk_factors: Array<{
    severity: string;
    name: string;
    description: string;
    contributing_signals: string[];
  }>;
  seller: {
    id: string;
    name: string | null;
    platform: string | null;
    platform_id: string | null;
    handle: string | null;
    phone: string | null;
    account_age: string;
    verification: string;
    location: string | null;
    last_active: string | null;
    network_summary: string;
    monthly_activity: number[];
  };
  signals: Array<{
    label: string;
    sub: string;
    value: string;
    type: string;
  }>;
  social_candidates?: PlatformCheckResult[];
}

export function formatPlatformName(platform: string | null | undefined): string {
  if (!platform) return "Not found";
  const names: Record<string, string> = {
    olx: "OLX",
    b2brazil: "B2Brazil",
  };
  return names[platform] || platform;
}

(function () {
  "use strict";

  const SAFELY_ENV: "local" | "production" = "local";
  const API_BASE =
    SAFELY_ENV === "local" ? "http://localhost:3000/api/v1" : "https://safely.sh/api/v1";

  // Same toggle, but for the actual website (not the /api/v1 path) -
  // kept as one source of truth alongside API_BASE.
  const SITE_BASE = SAFELY_ENV === "local" ? "http://localhost:3000" : "https://safely.sh";

  // Reads the session token auth-bridge.js relayed from the website.
  // Returns an empty object if the person isn't logged in.
  async function getAuthHeaders(): Promise<Record<string, string>> {
    try {
      const result = await chrome.storage.local.get("safely_session_token");
      const token = result.safely_session_token;
      return token ? { Authorization: "Bearer " + token } : {};
    } catch (e) {
      return {};
    }
  }

  (window as any).__safelyAPI = {
    SITE_BASE,

    analyze: async function (scrapedData: AnalyzePayload): Promise<AnalyzeResponse | null> {
      try {
        const authHeaders = await getAuthHeaders();
        const response = await fetch(API_BASE + "/analyze", {
          method: "POST",
          headers: Object.assign({ "Content-Type": "application/json" }, authHeaders),
          body: JSON.stringify(scrapedData),
        });
        const rawText = await response.text();
        if (!response.ok || rawText.startsWith("error")) {
          console.error("Safely: backend error:", rawText.substring(0, 300));
          if (response.status === 429) {
            const match = rawText.match(/RATE_LIMITED:(\d+)/);
            return {
              error: "rate_limited",
              retryAfterSeconds: match ? parseInt(match[1], 10) : null,
            } as AnalyzeResponse;
          }
          if (response.status === 401) {
            return { error: "unauthorized" } as AnalyzeResponse;
          }
          return null;
        }
        return JSON.parse(rawText);
      } catch (error: any) {
        console.error("Safely: failed to fetch analysis", error.message, error.stack);
        return null;
      }
    },

    checkSubscriptionStatus: async function (): Promise<string | null> {
      try {
        const authHeaders = await getAuthHeaders();
        const response = await fetch(API_BASE + "/billing/subscription-status", {
          headers: authHeaders,
        });
        if (!response.ok) return null;
        const data = await response.json();
        return data.status || null;
      } catch (error) {
        console.error("Safely: failed to check subscription status", error);
        return null;
      }
    },

    submitOutcome: async function (analysisId: string, action: "proceeded" | "aborted"): Promise<boolean> {
      try {
        const authHeaders = await getAuthHeaders();
        const response = await fetch(API_BASE + "/outcomes", {
          method: "POST",
          headers: Object.assign({ "Content-Type": "application/json" }, authHeaders),
          body: JSON.stringify({ analysis_id: analysisId, action }),
        });
        return response.ok;
      } catch (error) {
        console.error("Safely: failed to record outcome", error);
        return false;
      }
    },

    // verifySocialLink: async function (
    //   sellerId: string,
    //   url: string,
    // ): Promise<{ matched: boolean; matched_identifiers: string[]; confidence: string; message: string } | null> {
    //   try {
    //     const authHeaders = await getAuthHeaders();
    //     const response = await fetch(API_BASE + "/verify-social-link", {
    //       method: "POST",
    //       headers: Object.assign({ "Content-Type": "application/json" }, authHeaders),
    //       body: JSON.stringify({ seller_id: sellerId, url }),
    //     });
    //     if (!response.ok) return null;
    //     return await response.json();
    //   } catch (error) {
    //     console.error("Safely: failed to verify social link", error);
    //     return null;
    //   }
    // },
    submitReport: async function (reportData: Record<string, unknown>): Promise<any> {
      try {
        const authHeaders = await getAuthHeaders();
        const response = await fetch(API_BASE + "/report", {
          method: "POST",
          headers: Object.assign({ "Content-Type": "application/json" }, authHeaders),
          body: JSON.stringify(reportData),
        });
        const rawText = await response.text();
        if (!response.ok || rawText.startsWith("error")) {
          console.error("Safely: report error:", rawText.substring(0, 300));
          return response.status === 401 ? { error: "unauthorized" } : null;
        }
        return JSON.parse(rawText);
      } catch (error: any) {
        console.error("Safely: failed to submit report", error.message, error.stack);
        return null;
      }
    },

    fetchAnalysis: async function (): Promise<void> {
      await (window as any).__safelyScrapers.loadProtectedDomains();
      const platform = (window as any).__safelyScrapers.detectPlatform();
      if (platform === "unknown") {
        window.dispatchEvent(new CustomEvent("safely-analysis-finished"));
        return;
      }

      // Defense-in-depth: panel.js already gates this, but checking
      // again here keeps this safe even if something calls it directly.
      if (!(window as any).__safelyScrapers.isListingPage()) {
        window.dispatchEvent(new CustomEvent("safely-analysis-finished"));
        return;
      }

      const listing_url = window.location.href;

      let scraped: any = {};
      if ((window as any).__safelyScrapers.requiresClientSideScraping(platform)) {
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }

      const domainCheck = (window as any).__safelyScrapers.checkDomain();
      const payload: AnalyzePayload = {
        platform,
        listing_url,
        seller_id: null,
        listing_id: scraped.listing_id || null,
        title: scraped.title || null,
        price: scraped.price || null,
        description: scraped.description || null,
        category: null,
        image_urls: scraped.image_urls || null,
        posted_date: null,
        platform_id: scraped.platform_id || null,
        seller_name: scraped.seller_name || null,
        seller_handle: null,
        seller_phone: null,
        seller_profile_url: scraped.seller_profile_url || null,
        seller_join_date: scraped.seller_join_date || null,
        seller_location: scraped.seller_location || null,
        seller_last_active: scraped.seller_last_active || null,
        seller_website: scraped.seller_website || null,
        seller_verified: scraped.seller_verified || false,
        seller_rating: scraped.seller_rating || null,
        seller_total_products: scraped.seller_total_products || null,
        domain_check_status: domainCheck ? domainCheck.status : null,
        domain_check_real_name: domainCheck ? domainCheck.realName : null,
        domain_check_real_domain: domainCheck ? domainCheck.realDomain : null,
        domain_check_current_domain: domainCheck
          ? domainCheck.currentDomain || window.location.hostname
          : null,
        domain_check_current_html: domainCheck ? domainCheck.currentDomainHtml || null : null,
        domain_check_real_html: domainCheck ? domainCheck.realDomainHtml || null : null,
      };

      const data = await (window as any).__safelyAPI.analyze(payload);

      if (!data || data.error) {
        window.dispatchEvent(
          new CustomEvent("safely-analysis-finished", {
            detail: {
              error: data && data.error ? data.error : "generic",
              retryAfterSeconds: data && data.retryAfterSeconds,
            },
          }),
        );
        return;
      }

      (window as any).__safelyData = {
        analysisId: data.analysis_id,
        riskScore: data.risk_score,
        fraudReportCount: data.fraud_report_count,
        riskFactors: data.risk_factors || [],
        sellerId: data.seller.id,
        socialCandidates: data.social_candidates || [],
        seller: {
          name: data.seller.name || "Not found",
          platform: formatPlatformName(data.seller.platform || scraped.platform),
          platformId: data.seller.platform_id || null,
          handle: data.seller.handle || "Not found",
          phone: data.seller.phone || "Not found",
          accountAge: data.seller.account_age || "Not found",
          verification: data.seller.verification,
          location: data.seller.location || "Not found",
          lastActive: scraped.seller_last_active || data.seller.last_active || "Not found",
          networkSummary: data.seller.network_summary,
          monthlyActivity: data.seller.monthly_activity,
        },
        signals: data.signals.map((s: any) => ({
          label: s.label,
          sub: s.sub,
          value: s.value,
          type: s.type,
        })),
      };

      window.dispatchEvent(new CustomEvent("safely-data-ready"));
      window.dispatchEvent(new CustomEvent("safely-analysis-finished"));
    },
  };
})();
