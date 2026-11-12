-- GET /-/apm/v1/recent-packages lists the npm packages scored most recently (the website's sitemap reads it).
-- It walks this index from the newest analysis instead of scanning every stored analysis.

CREATE INDEX upstream_analysis_analyzed_at ON upstream_analysis (analyzed_at DESC);
