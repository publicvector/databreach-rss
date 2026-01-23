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
        <h2>Endpoints</h2>
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


if __name__ == "__main__":
    max_blogs = int(os.environ.get("MAX_BLOGS", 50))
    generate_static_site(max_blogs=max_blogs)

