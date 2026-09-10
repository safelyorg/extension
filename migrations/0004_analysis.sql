CREATE TABLE IF NOT EXISTS analysis (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    listing_id UUID NOT NULL REFERENCES listings(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    risk_score SMALLINT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level risk_level_type NOT NULL,
    signals JSONB NOT NULL,
    network_summary TEXT,
    claude_raw TEXT,
    confidence_level TEXT,
    confidence_reasoning TEXT,
    risk_factors JSONB,
    social_candidates JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analysis_listing_id ON analysis(listing_id);
CREATE INDEX IF NOT EXISTS idx_analysis_user_id ON analysis(user_id);
