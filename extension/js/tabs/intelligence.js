"use strict";
(async function () {
    "use strict";
    let wasm;
    try {
        const wasmUrl = chrome.runtime.getURL("pkg/wasm.js");
        wasm = await import(wasmUrl);
        await wasm.default();
        console.log("Safely: real WASM module loaded successfully");
    }
    catch (e) {
        console.warn("Safely: WASM blocked, using JS fallback");
        console.error("Safely: real WASM loading error was:", e);
        wasm = {
            default: async () => { },
            analyze_signals: (j) => {
                const signals = JSON.parse(j);
                const bad = signals.filter((s) => s.type === "bad" || s.type === "caution").length;
                const level = bad === 0 ? "low" : bad === 1 ? "caution" : "high";
                const text = bad === 0
                    ? "All " + signals.length + " signals checked. No red flags detected."
                    : bad + " of " + signals.length + " signals need your attention.";
                return JSON.stringify({ level, text });
            },
            // Redesigned to match the Recommended Checks card style - separate
            // rounded cards with spacing between them, instead of a single
            // bordered list with colored differentiator lines. The status
            // word itself is now the only color differentiation.
            build_signal_rows: (j) => {
                const signals = JSON.parse(j);
                const COLORS = {
                    good: "#35d0a6",
                    caution: "#f2b84c",
                    info: "#8e8e93",
                };
                return signals
                    .map((s) => {
                    const color = COLORS[s.type] || "#ff5d5d";
                    return ('<div class="safely-check-card">' +
                        '<div style="display:flex;justify-content:space-between;align-items:baseline;gap:8px;">' +
                        '<div class="safely-check-title">' +
                        window.escapeHtml(capitalizeFirst(s.label)) +
                        "</div>" +
                        '<div style="font-weight:700;white-space:nowrap;font-size:13px;color:' +
                        color +
                        ';">' +
                        window.escapeHtml(capitalizeFirst(s.value)) +
                        "</div></div>" +
                        '<div class="safely-check-body">' +
                        window.escapeHtml(capitalizeFirst(s.sub) || "") +
                        "</div></div>");
                })
                    .join("");
            },
        };
    }
    if (!window.__safelyAddTab)
        return;
    const PLATFORM_ORDER = [
        "Facebook", "LinkedIn", "TikTok", "Instagram", "Reddit", "Trustpilot",
        "Reviews", "Contact (Facebook)", "Contact (LinkedIn)", "Contact (Web)",
    ];
    function buildSocialPresenceSection() {
        const pageData = window.__safelyData;
        const results = pageData.socialCandidates || [];
        if (results.length === 0)
            return "";
        // Merge every variant's results into one, deduplicated list per
        // real platform - the same platform can be checked with several
        // real name variants, and the same, genuine link often shows up
        // more than once across them.
        const grouped = {};
        results.forEach((entry) => {
            if (!(entry.platform in grouped))
                grouped[entry.platform] = [];
            entry.candidates.forEach((c) => {
                if (!grouped[entry.platform].some((existing) => existing.url === c.url)) {
                    grouped[entry.platform].push(c);
                }
            });
        });
        const order = PLATFORM_ORDER.filter((p) => p in grouped).concat(Object.keys(grouped).filter((p) => !PLATFORM_ORDER.includes(p)));
        const groupsHTML = order
            .map((platform, index) => {
            const isLast = index === order.length - 1;
            const borderStyle = isLast ? "" : "border-bottom:1px solid rgba(255,255,255,0.08);";
            const links = grouped[platform];
            const body = links.length === 0
                ? '<div style="padding:4px;font-size:12px;color:#8e8e93;">Not found</div>'
                : links
                    .map((link) => '<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 4px;">' +
                    '<span style="color:#8e8e93;flex-shrink:0;margin-top:1px;">&#8226;</span>' +
                    '<a href="' +
                    window.escapeHtml(link.url) +
                    '" target="_blank" rel="noopener noreferrer" style="font-size:12px;line-height:1.4;color:#f2f1ed;flex:1;min-width:0;text-decoration:none;" onmouseover="this.style.color=\'#6fb3ef\'" onmouseout="this.style.color=\'#f2f1ed\'">' +
                    window.escapeHtml(link.title) +
                    "</a></div>")
                    .join("");
            return ('<div style="padding:10px 0;' +
                borderStyle +
                '">' +
                '<div style="font-size:11px;font-weight:700;color:#8e8e93;text-transform:uppercase;letter-spacing:0.4px;margin-bottom:4px;padding:0 4px;">' +
                window.escapeHtml(platform) +
                "</div>" +
                body +
                "</div>");
        })
            .join("");
        return ('<div class="safely-section-label" style="margin-top:18px">Social presence check</div>' +
            '<div class="safely-check-card">' +
            '<button id="safely-social-toggle" type="button" style="width:100%;text-align:left;background:none;border:none;cursor:pointer;padding:0;font-size:13px;font-weight:600;color:#f2f1ed;display:flex;justify-content:space-between;align-items:center;">' +
            '<span id="safely-social-toggle-text">Click to drop down</span><span id="safely-social-arrow">&#9662;</span>' +
            "</button>" +
            '<div id="safely-social-dropdown" style="display:none;margin-top:12px;">' +
            groupsHTML +
            "</div></div>");
    }
    function attachSocialPresenceListeners() {
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
    function buildIntelligenceTab() {
        const pageData = window.__safelyData;
        const sigResult = JSON.parse(wasm.analyze_signals(JSON.stringify(pageData.signals)));
        const summaryLvl = sigResult.level;
        const summaryText = sigResult.text;
        return ('<div class="safely-intel-summary safely-alert-' +
            summaryLvl +
            '"><span>&#9679;</span><span>' +
            summaryText +
            "</span></div>" +
            '<div class="safely-section-label" style="margin-top:14px">Listing signals</div><div style="display:flex;flex-direction:column;gap:8px">' +
            wasm.build_signal_rows(JSON.stringify(pageData.signals)) +
            "</div>" +
            buildSocialPresenceSection() +
            (function () {
                const priceSignal = pageData.signals.find((s) => s.label === "Price analysis");
                const verdict = priceSignal ? priceSignal.value : "unknown";
                const reasoning = priceSignal ? priceSignal.sub : "No price data available.";
                const verdictClass = verdict === "normal" ? "low" : verdict === "unknown" ? "low" : "caution";
                return ('<div class="safely-section-label" style="margin-top:18px">Price vs market</div>' +
                    '<div class="safely-network-alert safely-alert-' +
                    verdictClass +
                    '" style="margin-top:8px">' +
                    "<span>&#9679;</span>" +
                    "<div>" +
                    '<div style="font-weight:600;margin-bottom:4px">' +
                    verdict.charAt(0).toUpperCase() +
                    verdict.slice(1) +
                    "</div>" +
                    '<div style="font-size:12px;opacity:0.85">' +
                    reasoning +
                    "</div>" +
                    "</div>" +
                    "</div>");
            })() +
            '<div class="safely-section-label" style="margin-top:18px">Recommended checks</div><div style="display:flex;flex-direction:column;gap:8px">' +
            '<div class="safely-check-card"><div class="safely-check-title">Ask for a live video call</div><div class="safely-check-body">Verify the item is physically in the seller\'s hands before sending any payment.</div></div>' +
            '<div class="safely-check-card"><div class="safely-check-title">Check IMEI on delivery</div><div class="safely-check-body">Dial *#06# on the device and confirm the number matches what the seller declared at deal creation.</div></div>' +
            '<div class="safely-check-card"><div class="safely-check-title">Do not pay to number in listing</div><div class="safely-check-body">A phone number in the listing could route your payment outside Safely escrow protection.</div></div></div>' +
            buildRiskFactorsSection(pageData.riskFactors));
    }
    const SEVERITY_COLORS = {
        hard: "#ff5d5d",
        compound: "#f2b84c",
        soft: "#8e8e93",
    };
    const SEVERITY_LABELS = {
        hard: "Confirmed",
        compound: "Pattern match",
        soft: "Worth noting",
    };
    function capitalizeFirst(str) {
        if (!str)
            return str;
        return str.charAt(0).toUpperCase() + str.slice(1);
    }
    function buildRiskFactorsSection(riskFactors) {
        if (!riskFactors || riskFactors.length === 0)
            return "";
        const rows = riskFactors
            .map((factor) => {
            const color = SEVERITY_COLORS[factor.severity] || "#8e8e93";
            const severityLabel = SEVERITY_LABELS[factor.severity] || factor.severity;
            const shortTitle = factor.contributing_signals && factor.contributing_signals.length > 0
                ? factor.contributing_signals.join(" + ")
                : capitalizeFirst(factor.name.replace(/_/g, " "));
            return ('<div class="safely-check-card">' +
                '<div style="display:flex;justify-content:space-between;align-items:baseline;gap:8px;">' +
                '<div class="safely-check-title">' +
                window.escapeHtml(shortTitle) +
                "</div>" +
                '<div style="font-weight:700;white-space:nowrap;font-size:11px;color:' +
                color +
                ';">' +
                window.escapeHtml(severityLabel) +
                "</div></div>" +
                '<div class="safely-check-body">' +
                window.escapeHtml(factor.description) +
                "</div></div>");
        })
            .join("");
        return ('<div class="safely-section-label" style="margin-top:18px">Risk Factors</div><div style="display:flex;flex-direction:column;gap:8px">' +
            rows +
            "</div>");
    }
    window.__safelyAddTab("intelligence", "Intelligence", buildIntelligenceTab(), '<svg viewBox="0 0 24 24" fill="none" stroke="#8e8e93" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 010 8.48"/><path d="M19.07 4.93a10 10 0 010 14.14"/><path d="M7.76 16.24a6 6 0 010-8.48"/><path d="M4.93 19.07a10 10 0 010-14.14"/></svg>', attachSocialPresenceListeners);
    window.addEventListener("safely-data-ready", () => {
        const tabEl = document.getElementById("safely-tab-intelligence");
        if (tabEl) {
            tabEl.innerHTML = buildIntelligenceTab();
            attachSocialPresenceListeners();
        }
    });
})();
