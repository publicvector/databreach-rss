# Data Breach RSS Feed Generator

A Python tool that aggregates data breach notifications from multiple sources and generates RSS/Atom feeds.

## Sources

### API Sources (No Authentication Required)
- **ransomware.live** - Real-time ransomware victim tracking via public API
- **databreaches.net** - Breach news RSS feed
- **HIPAA Journal** - Healthcare breach news RSS feed
- **BleepingComputer** - Security news RSS feed

### Web Scrapers (requests/BeautifulSoup)
- **HHS OCR** - Federal HIPAA breach portal
- **California AG** - State breach registry
- **breachsense.com** - Ransomware tracking site

### State Registries (Selenium Required)
- **Maine AG** - Detailed breach notifications
- **Texas AG** - State breach registry
- **Washington AG** - State breach notifications
- **Hawaii DCCA** - State breach registry

## Installation

```bash
# Basic installation
pip install -r requirements.txt

# For Selenium-based sources (optional)
pip install selenium webdriver-manager

# You'll also need Chrome/Chromium installed
# macOS: brew install chromedriver
# Ubuntu: apt-get install chromium-chromedriver
```

## Usage

### Generate RSS Feed

```bash
# Basic usage - generates RSS feed
python breach_rss_full.py -o breaches.xml

# Generate RSS + Atom feeds
python breach_rss_full.py -o breaches.xml --format both

# Generate all formats (RSS, JSON, CSV)
python breach_rss_full.py -o breaches.xml --json breaches.json --csv breaches.csv

# Skip Selenium sources (faster, no browser needed)
python breach_rss_full.py -o breaches.xml --no-selenium
```

### Run as Web Server

```bash
# Start Flask server on port 5000
python breach_rss_full.py --serve

# Custom port
python breach_rss_full.py --serve --port 8080
```

Server endpoints:
- `/rss` - RSS feed
- `/atom` - Atom feed
- `/json` - JSON data
- `/refresh` - Force refresh data

### Scheduled Updates

Use cron for scheduled updates:

```bash
# Update every hour
0 * * * * /usr/bin/python3 /path/to/breach_rss_full.py -o /var/www/feeds/breaches.xml

# Update every 6 hours with all formats
0 */6 * * * /usr/bin/python3 /path/to/breach_rss_full.py -o /var/www/feeds/breaches.xml --json /var/www/feeds/breaches.json
```

## Output Format

### RSS Feed Structure

```xml
<item>
  <title>Company Name</title>
  <link>https://source-url.com/breach-details</link>
  <description>
    Description of the breach
    Threat Actor: LockBit
    Records Affected: 50,000
    Location: California
    Source: ransomware.live
    Type: Ransomware
  </description>
  <pubDate>Mon, 23 Dec 2024 00:00:00 +0000</pubDate>
  <category>Ransomware</category>
  <category>ransomware.live</category>
</item>
```

### JSON Output

```json
{
  "company_name": "Acme Corp",
  "date_reported": "2024-12-23",
  "source": "ransomware.live",
  "url": "https://...",
  "description": "...",
  "records_affected": "50000",
  "state_records_affected": "",
  "location": "US",
  "threat_actor": "LockBit",
  "breach_type": "Ransomware"
}
```

## Integration with Your Streamlit Dashboard

You can integrate the feed generator with your existing dashboard:

```python
from breach_rss_full import BreachDataCollector

# In your Streamlit app
collector = BreachDataCollector(use_selenium=True)
entries = collector.collect_all()

# Convert to DataFrame for display
df = pd.DataFrame([e.to_dict() for e in entries])
st.dataframe(df)
```

## Adding New Sources

To add a new data source:

1. Create a fetch method in `BreachDataCollector`:

```python
def fetch_new_source(self, limit: int = 50) -> List[BreachEntry]:
    entries = []
    # Your scraping/API logic here
    entries.append(BreachEntry(
        company_name="...",
        date_reported="...",
        source="New Source",
        url="...",
        # ... other fields
    ))
    return entries
```

2. Add it to `collect_all()`:

```python
basic_sources = [
    # ... existing sources
    ('New Source', self.fetch_new_source),
]
```

## API Reference

### ransomware.live API

Free public API, no authentication required:

```bash
# Get recent victims
curl https://api.ransomware.live/v2/recentvictims

# Get victims by group
curl https://api.ransomware.live/v2/groupvictims/lockbit

# Get victims by country
curl https://api.ransomware.live/v2/countryvictims/US

# Search
curl https://api.ransomware.live/v2/searchvictims/healthcare
```

### databreaches.net RSS

```
https://databreaches.net/feed/
```

## Deployment Options

### Docker

```dockerfile
FROM python:3.11-slim

# Install Chrome for Selenium
RUN apt-get update && apt-get install -y chromium chromium-driver

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY *.py .

# Run as server
CMD ["python", "breach_rss_full.py", "--serve", "--port", "8080"]
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name breaches.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
    }
    
    # Cache the RSS feed for 15 minutes
    location /rss {
        proxy_pass http://127.0.0.1:5000/rss;
        proxy_cache_valid 200 15m;
    }
}
```

## Rate Limiting & Best Practices

- The tool respects robots.txt implicitly through reasonable request intervals
- Parallel fetching is used for non-Selenium sources
- Selenium sources run sequentially to avoid resource conflicts
- Consider adding delays if running very frequently
- HHS OCR and state AG sites may have rate limits

## License

MIT License - Use freely for research and monitoring purposes.

## Contributing

Pull requests welcome! Ideas for improvement:
- Additional state registries (NY, FL, etc.)
- More ransomware trackers
- Better deduplication
- Email/Slack notifications
- Database persistence
