#!/usr/bin/env python3
"""
Static Site Generator for Data Breach Blog

Generates static JSON and HTML files for GitHub Pages hosting.
Run periodically via GitHub Actions.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from breach_rss_full import BreachDataCollector, RSSFeedGenerator
from blog_generator import BlogGenerator

OUTPUT_DIR = Path("docs")


def generate_static_site(max_blogs: int = 50):
    """Generate all static files for GitHub Pages"""

    # Create output directory
    OUTPUT_DIR.mkdir(exist_ok=True)

    print("Collecting breach data...")
    collector = BreachDataCollector(use_selenium=False)
    entries = collector.collect_all(include_selenium=False, max_per_source=25)

    # Sort by date (newest first)
    def get_sort_date(e):
        try:
            from datetime import datetime
            for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%B %d, %Y']:
                try:
                    return datetime.strptime(e.date_reported[:10], fmt)
                except:
                    continue
        except:
            pass
        return datetime.min

    entries.sort(key=get_sort_date, reverse=True)
    print(f"Collected {len(entries)} entries")

    # Generate RSS feed
    print("Generating RSS feed...")
    feed_gen = RSSFeedGenerator(
        title="Data Breach & Ransomware Feed",
        link="https://publicvector.github.io/databreach-rss/",
        description="Aggregated data breach notifications"
    )
    feed_gen.add_entries(entries)

    with open(OUTPUT_DIR / "rss.xml", "w") as f:
        f.write(feed_gen.generate_rss())

    with open(OUTPUT_DIR / "atom.xml", "w") as f:
        f.write(feed_gen.generate_atom())

    # Generate JSON data
    print("Generating JSON data...")
    with open(OUTPUT_DIR / "data.json", "w") as f:
        json.dump([e.to_dict() for e in entries], f, indent=2)

    # Generate blogs
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if api_key:
        print(f"Generating blogs (up to {max_blogs})...")
        generator = BlogGenerator(
            api_key=api_key,
            cache_dir=str(OUTPUT_DIR / "blog_cache")
        )

        result = generator.generate_batch(entries, limit=max_blogs)

        with open(OUTPUT_DIR / "blogs.json", "w") as f:
            json.dump(result, f, indent=2)

        print(f"Generated {result['meta']['generated_count']} blogs, "
              f"cached {result['meta']['cached_count']}, "
              f"skipped {result['meta']['skipped_count']}")
    else:
        print("ANTHROPIC_API_KEY not set, skipping blog generation")
        with open(OUTPUT_DIR / "blogs.json", "w") as f:
            json.dump({"blogs": [], "meta": {"error": "API key not configured"}}, f)

    # Generate index.html
    print("Generating index.html...")
    generate_index_html(entries, result if api_key else None)

    # Generate breaches.html
    print("Generating breaches.html...")
    generate_breaches_html([e.to_dict() for e in entries])

    # Generate timestamp
    with open(OUTPUT_DIR / "last_updated.json", "w") as f:
        json.dump({"timestamp": datetime.now(timezone.utc).isoformat()}, f)

    print(f"Static site generated in {OUTPUT_DIR}/")


def generate_index_html(entries, blog_result):
    """Generate a simple index.html"""

    blog_count = len(blog_result['blogs']) if blog_result else 0

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Data Breach RSS Feed</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        h1 {{ color: #c0392b; }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        a {{ color: #2980b9; }}
        .endpoint {{
            background: #ecf0f1;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            display: inline-block;
            margin: 5px 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
        }}
        .stat {{
            background: #3498db;
            color: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-number {{ font-size: 2em; font-weight: bold; }}
        .blog {{
            border-left: 4px solid #c0392b;
            padding-left: 15px;
            margin: 15px 0;
        }}
        .blog h3 {{ margin: 0 0 10px 0; }}
        .blog-meta {{ color: #666; font-size: 0.9em; }}
    </style>
</head>
<body>
    <h1>Data Breach RSS Feed</h1>

    <div class="card">
        <h2>Browse</h2>
        <p><span class="endpoint"><a href="breaches.html">breaches.html</a></span> - All breaches (styled view with search)</p>
        <h2>Data Feeds</h2>
        <p><span class="endpoint"><a href="rss.xml">rss.xml</a></span> - RSS Feed</p>
        <p><span class="endpoint"><a href="atom.xml">atom.xml</a></span> - Atom Feed</p>
        <p><span class="endpoint"><a href="data.json">data.json</a></span> - Raw breach data (JSON)</p>
        <p><span class="endpoint"><a href="blogs.json">blogs.json</a></span> - AI-generated blog posts (JSON)</p>
    </div>

    <div class="card">
        <h2>Statistics</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-number">{len(entries)}</div>
                <div>Breach Entries</div>
            </div>
            <div class="stat">
                <div class="stat-number">{blog_count}</div>
                <div>Blog Posts</div>
            </div>
        </div>
    </div>

    <div class="card">
        <h2>Recent Blog Posts</h2>
"""

    if blog_result and blog_result['blogs']:
        for blog in blog_result['blogs'][:5]:
            html += f"""
        <div class="blog">
            <h3>{blog['company_name']}</h3>
            <p class="blog-meta">Quality Score: {blog['quality_score']} | Generated: {blog['generated_at'][:10]}</p>
            <p>{blog['what_happened'][:300]}...</p>
        </div>
"""
    else:
        html += "<p>No blogs generated yet.</p>"

    html += """
    </div>

    <div class="card">
        <p><small>Updated automatically via GitHub Actions.
        <a href="https://github.com/publicvector/databreach-rss">View source on GitHub</a></small></p>
    </div>
</body>
</html>
"""

    with open(OUTPUT_DIR / "index.html", "w") as f:
        f.write(html)


def generate_breaches_html(entries):
    """Generate a styled HTML page showing all breach entries"""

    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>All Data Breaches</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }
        h1 { color: #c0392b; }
        a { color: #2980b9; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .nav {
            margin-bottom: 20px;
        }
        .nav a {
            margin-right: 15px;
            padding: 8px 15px;
            background: #3498db;
            color: white;
            border-radius: 4px;
        }
        .nav a:hover { background: #2980b9; text-decoration: none; }
        .filters {
            background: white;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .filters input {
            padding: 10px;
            width: 300px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        .breach-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #c0392b;
        }
        .breach-card h3 {
            margin: 0 0 10px 0;
            color: #2c3e50;
        }
        .breach-card h3 a { color: #2c3e50; }
        .breach-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 15px;
            margin: 10px 0;
            font-size: 0.9em;
        }
        .meta-item {
            background: #ecf0f1;
            padding: 4px 10px;
            border-radius: 4px;
        }
        .meta-item.source { background: #3498db; color: white; }
        .meta-item.type { background: #9b59b6; color: white; }
        .meta-item.actor { background: #e74c3c; color: white; }
        .meta-item.records { background: #27ae60; color: white; }
        .meta-item.location { background: #f39c12; color: white; }
        .description {
            color: #555;
            line-height: 1.6;
            margin-top: 10px;
        }
        .breach-details {
            background: #f8f9fa;
            padding: 12px 15px;
            border-radius: 6px;
            margin: 12px 0;
        }
        .detail-row {
            padding: 4px 0;
            font-size: 0.95em;
        }
        .detail-label {
            font-weight: 600;
            color: #2c3e50;
        }
        .count {
            color: #666;
            margin-bottom: 15px;
        }
        .hidden { display: none; }
    </style>
</head>
<body>
    <div class="nav">
        <a href="index.html">Dashboard</a>
        <a href="breaches.html">All Breaches</a>
        <a href="rss.xml">RSS Feed</a>
    </div>

    <h1>All Data Breaches</h1>

    <div class="filters">
        <input type="text" id="search" placeholder="Search breaches..." onkeyup="filterBreaches()">
    </div>

    <p class="count">Showing <span id="visible-count">""" + str(len(entries)) + """</span> of """ + str(len(entries)) + """ breaches</p>

    <div id="breaches">
"""

    for entry in entries:
        desc = entry.get('description', '')[:300]
        if len(entry.get('description', '')) > 300:
            desc += '...'

        # Build meta tags
        meta_html = f'<span class="meta-item source">{entry.get("source", "Unknown")}</span>'
        meta_html += f'<span class="meta-item type">{entry.get("breach_type", "Data Breach")}</span>'

        if entry.get('threat_actor'):
            meta_html += f'<span class="meta-item actor">🎭 {entry["threat_actor"]}</span>'

        date_str = entry.get('date_reported', '')[:10] if entry.get('date_reported') else ''

        url = entry.get('url', '#')
        company = entry.get('company_name', 'Unknown')

        # Build details section for location and records
        details_html = ""

        location = entry.get('location', '')
        if location and location not in ['Unknown', 'N/A', '']:
            details_html += f'<div class="detail-row"><span class="detail-label">📍 Location:</span> {location}</div>'

        records = entry.get('records_affected', '')
        if records and records not in ['Unknown', 'N/A', '']:
            details_html += f'<div class="detail-row"><span class="detail-label">📊 Total Affected:</span> {records}</div>'

        state_records = entry.get('state_records_affected', '')
        if state_records and state_records not in ['Unknown', 'N/A', '']:
            # Try to determine which state from source
            state_name = ''
            source = entry.get('source', '')
            if 'Maine' in source:
                state_name = 'Maine'
            elif 'Texas' in source:
                state_name = 'Texas'
            elif 'Washington' in source:
                state_name = 'Washington'
            elif 'California' in source:
                state_name = 'California'

            if state_name:
                details_html += f'<div class="detail-row"><span class="detail-label">🏛️ {state_name} Residents Affected:</span> {state_records}</div>'
            else:
                details_html += f'<div class="detail-row"><span class="detail-label">🏛️ State Residents Affected:</span> {state_records}</div>'

        html += f"""
        <div class="breach-card" data-search="{company.lower()} {entry.get('source', '').lower()} {entry.get('threat_actor', '').lower()} {entry.get('breach_type', '').lower()} {location.lower()}">
            <h3><a href="{url}" target="_blank">{company}</a></h3>
            <div class="breach-meta">
                <span class="meta-item">📅 {date_str}</span>
                {meta_html}
            </div>
            <div class="breach-details">
                {details_html if details_html else '<div class="detail-row"><span class="detail-label">ℹ️</span> No additional details available</div>'}
            </div>
            <p class="description">{desc if desc else 'No description available.'}</p>
        </div>
"""

    html += """
    </div>

    <script>
        function filterBreaches() {
            const search = document.getElementById('search').value.toLowerCase();
            const cards = document.querySelectorAll('.breach-card');
            let visible = 0;

            cards.forEach(card => {
                const text = card.getAttribute('data-search');
                if (text.includes(search)) {
                    card.classList.remove('hidden');
                    visible++;
                } else {
                    card.classList.add('hidden');
                }
            });

            document.getElementById('visible-count').textContent = visible;
        }
    </script>
</body>
</html>
"""

    with open(OUTPUT_DIR / "breaches.html", "w") as f:
        f.write(html)


if __name__ == "__main__":
    max_blogs = int(os.environ.get("MAX_BLOGS", 50))
    generate_static_site(max_blogs=max_blogs)

