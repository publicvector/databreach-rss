#!/usr/bin/env python3
"""
Data Breach RSS Feed Generator - Full Version

Aggregates data breach notifications from 30+ sources:

STATE REGISTRIES (require Selenium):
- Maine AG, Texas AG, Washington AG, California AG

FEDERAL SOURCES:
- HHS OCR (HIPAA breaches)

RANSOMWARE TRACKERS:
- ransomware.live API, breachsense.com, Red Packet Security

NEWS SOURCES (RSS):
- databreaches.net, HIPAA Journal, BleepingComputer
- Krebs on Security, The Record, The Hacker News
- SecurityWeek, Dark Reading, CyberScoop, SC Media
- Security Affairs, HackRead, WeLiveSecurity
- Graham Cluley, Tripwire

HEALTHCARE/FINANCE:
- DataBreachToday, BankInfoSecurity

THREAT INTEL (Vendor Blogs):
- Cyble, Sophos, Kaspersky Securelist
- SentinelOne Labs, Malwarebytes

Outputs: RSS, Atom, JSON, CSV
"""

import requests
import pandas as pd
from bs4 import BeautifulSoup
from feedgen.feed import FeedGenerator
from datetime import datetime, timedelta, timezone
import time
import re
import json
import hashlib
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import StringIO
import feedparser
import logging
import argparse
import os

# Selenium imports (optional)
try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class BreachEntry:
    """Normalized breach entry from any source"""
    company_name: str
    date_reported: str
    source: str
    url: str
    description: str = ""
    records_affected: str = "Unknown"
    state_records_affected: str = ""
    location: str = ""
    threat_actor: str = ""
    breach_type: str = "Data Breach"
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @property
    def unique_id(self) -> str:
        """Generate unique ID for deduplication based on source (legacy)"""
        # Normalize company name for better deduplication
        normalized_name = re.sub(r'[^\w\s]', '', self.company_name.lower())
        content = f"{normalized_name}{self.date_reported[:10] if len(self.date_reported) > 10 else self.date_reported}{self.source}"
        return hashlib.md5(content.encode()).hexdigest()

    @property
    def case_id(self) -> str:
        """Generate case ID for cross-source deduplication (one entry per breach case)"""
        # Normalize company name - remove punctuation, lowercase, strip common suffixes
        normalized_name = re.sub(r'[^\w\s]', '', self.company_name.lower())
        # Remove common corporate suffixes for better matching
        for suffix in [' inc', ' llc', ' ltd', ' corp', ' corporation', ' company', ' co']:
            if normalized_name.endswith(suffix):
                normalized_name = normalized_name[:-len(suffix)]
        normalized_name = normalized_name.strip()

        # Extract just the date portion (YYYY-MM or YYYY-MM-DD) for matching
        date_part = ''
        if self.date_reported:
            # Try to extract YYYY-MM from various date formats
            date_match = re.search(r'(\d{4})-(\d{2})', self.date_reported)
            if date_match:
                date_part = f"{date_match.group(1)}-{date_match.group(2)}"
            else:
                # Try MM/YYYY or MM/DD/YYYY format
                date_match = re.search(r'(\d{1,2})/\d{1,2}/(\d{4})', self.date_reported)
                if date_match:
                    date_part = f"{date_match.group(2)}-{date_match.group(1).zfill(2)}"

        content = f"{normalized_name}{date_part}"
        return hashlib.md5(content.encode()).hexdigest()


# =============================================================================
# SELENIUM DRIVER HELPER
# =============================================================================

def create_chrome_driver() -> Optional['webdriver.Chrome']:
    """Create a headless Chrome driver"""
    if not SELENIUM_AVAILABLE:
        logger.warning("Selenium not installed. State registry scraping disabled.")
        return None
    
    try:
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        chrome_options.add_experimental_option('useAutomationExtension', False)
        
        driver = webdriver.Chrome(options=chrome_options)
        return driver
    except Exception as e:
        logger.error(f"Failed to create Chrome driver: {e}")
        return None


# =============================================================================
# DATA COLLECTORS
# =============================================================================

class BreachDataCollector:
    """Collects breach data from multiple sources"""
    
    def __init__(self, use_selenium: bool = True, timeout: int = 30):
        self.use_selenium = use_selenium and SELENIUM_AVAILABLE
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def _safe_request(self, url: str) -> Optional[requests.Response]:
        """Make a safe HTTP request with error handling"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for {url}: {e}")
            return None

    # =========================================================================
    # RANSOMWARE.LIVE API
    # =========================================================================
    def fetch_ransomware_live(self, limit: int = 30, us_only: bool = True) -> List[BreachEntry]:
        """Fetch recent victims from ransomware.live API (free, no auth)

        Args:
            limit: Maximum entries to return
            us_only: If True, only include US-based victims
        """
        entries = []
        url = "https://api.ransomware.live/v2/recentvictims"

        logger.info("Fetching from ransomware.live API...")
        response = self._safe_request(url)

        if not response:
            return entries

        try:
            data = response.json()
            for victim in data:
                # Filter to US only if enabled
                country = victim.get('country', '').upper()
                if us_only and country not in ('US', 'USA', 'UNITED STATES'):
                    continue

                # Handle nested group info
                group_name = victim.get('group_name', '')
                if not group_name and 'group' in victim:
                    group_name = victim['group'] if isinstance(victim['group'], str) else victim['group'].get('name', '')

                # Use attackdate (when posted) or discovered as fallback
                # Truncate microseconds for cleaner parsing
                raw_date = victim.get('attackdate', victim.get('discovered', ''))
                if raw_date and '.' in raw_date:
                    raw_date = raw_date.split('.')[0]  # Remove microseconds

                entries.append(BreachEntry(
                    company_name=victim.get('victim', 'Unknown'),
                    date_reported=raw_date,
                    source='Ransomware.live',
                    url=victim.get('url', f"https://www.ransomware.live/search?query={victim.get('victim', '')}"),
                    description=victim.get('activity', victim.get('description', ''))[:500],
                    location=victim.get('country', ''),
                    threat_actor=group_name,
                    breach_type='Ransomware'
                ))

                if len(entries) >= limit:
                    break

            logger.info(f"Fetched {len(entries)} US entries from ransomware.live")
        except (json.JSONDecodeError, KeyError) as e:
            logger.error(f"Failed to parse ransomware.live response: {e}")

        return entries

    # =========================================================================
    # DATABREACHES.NET RSS
    # =========================================================================
    def fetch_databreaches_net(self, limit: int = 50) -> List[BreachEntry]:
        """Fetch from databreaches.net RSS feed"""
        entries = []
        url = "https://databreaches.net/feed/"
        
        logger.info("Fetching from databreaches.net RSS...")
        
        try:
            feed = feedparser.parse(url)
            for item in feed.entries[:limit]:
                date_str = getattr(item, 'published', getattr(item, 'updated', ''))
                
                description = ''
                if hasattr(item, 'summary'):
                    soup = BeautifulSoup(item.summary, 'html.parser')
                    description = soup.get_text()[:500]
                
                entries.append(BreachEntry(
                    company_name=item.get('title', 'Unknown'),
                    date_reported=date_str,
                    source='DataBreaches.net',
                    url=item.get('link', ''),
                    description=description,
                    breach_type='Data Breach'
                ))
            logger.info(f"Fetched {len(entries)} entries from databreaches.net")
        except Exception as e:
            logger.error(f"Failed to fetch databreaches.net: {e}")
        
        return entries

    # =========================================================================
    # BREACHSENSE.COM SCRAPER
    # =========================================================================
    def fetch_breachsense(self, limit: int = 50) -> List[BreachEntry]:
        """Scrape recent breaches from breachsense.com"""
        entries = []
        base_url = "https://www.breachsense.com"
        url = f"{base_url}/breaches/"
        
        logger.info("Fetching from breachsense.com...")
        response = self._safe_request(url)
        
        if not response:
            return entries
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all breach article cards
            articles = soup.find_all('a', href=lambda x: x and '-data-breach' in str(x))
            
            for link in articles[:limit]:
                href = link.get('href', '')
                if not href:
                    continue
                
                # Get the title
                title_el = link.find(['h3', 'h2', 'h4'])
                title = title_el.get_text(strip=True) if title_el else ''
                
                if not title:
                    title = link.get_text(strip=True)
                
                company_name = title.replace('Data Breach', '').replace('data-breach', '').strip()
                
                # Look for threat actor in parent container
                parent = link.find_parent(['article', 'div', 'section'])
                threat_actor = ''
                date_str = ''  # Don't default to today - let _parse_date handle it

                if parent:
                    text = parent.get_text()

                    # Extract threat actor
                    actor_patterns = [
                        r'Threat Actor[:\s]+(\w+)',
                        r'threat actor[:\s]+(\w+)',
                        r'Group[:\s]+(\w+)',
                    ]
                    for pattern in actor_patterns:
                        match = re.search(pattern, text)
                        if match:
                            threat_actor = match.group(1)
                            break

                    # Extract date - try multiple patterns
                    date_patterns = [
                        r'((?:Dec|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov)[a-z]*\s+\d{1,2},?\s*\d{4})',
                        r'(\d{1,2}/\d{1,2}/\d{2,4})',
                        r'(\d{4}-\d{2}-\d{2})',
                        r'(\d{1,2}\s+(?:Dec|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov)[a-z]*\s+\d{4})',
                    ]
                    for pattern in date_patterns:
                        date_match = re.search(pattern, text, re.IGNORECASE)
                        if date_match:
                            date_str = date_match.group(1)
                            break
                
                full_url = f"{base_url}{href}" if href.startswith('/') else href
                
                if company_name:
                    entries.append(BreachEntry(
                        company_name=company_name,
                        date_reported=date_str,
                        source='BreachSense',
                        url=full_url,
                        threat_actor=threat_actor,
                        breach_type='Ransomware'
                    ))
            
            logger.info(f"Fetched {len(entries)} entries from breachsense.com")
        except Exception as e:
            logger.error(f"Failed to parse breachsense.com: {e}")
        
        return entries

    # =========================================================================
    # HIPAA JOURNAL RSS
    # =========================================================================
    def fetch_hipaa_journal(self, limit: int = 30) -> List[BreachEntry]:
        """Fetch from HIPAA Journal RSS feed"""
        entries = []
        urls_to_try = [
            "https://www.hipaajournal.com/feed/",
            "https://www.hipaajournal.com/category/hipaa-breach-news/feed/",
        ]
        
        logger.info("Fetching from HIPAA Journal RSS...")
        
        breach_keywords = ['breach', 'hack', 'ransomware', 'exposed', 'attack', 
                          'hipaa', 'leak', 'cyberattack', 'data']
        
        for url in urls_to_try:
            try:
                feed = feedparser.parse(url)
                if not feed.entries:
                    continue
                    
                for item in feed.entries[:limit]:
                    title = item.get('title', '').lower()
                    if any(kw in title for kw in breach_keywords):
                        date_str = getattr(item, 'published', getattr(item, 'updated', ''))
                        
                        description = ''
                        if hasattr(item, 'summary'):
                            soup = BeautifulSoup(item.summary, 'html.parser')
                            description = soup.get_text()[:500]
                        
                        entries.append(BreachEntry(
                            company_name=item.get('title', 'Unknown'),
                            date_reported=date_str,
                            source='HIPAA Journal',
                            url=item.get('link', ''),
                            description=description,
                            breach_type='Healthcare Breach'
                        ))
                
                if entries:
                    break
                    
            except Exception as e:
                logger.warning(f"Failed to fetch {url}: {e}")
        
        logger.info(f"Fetched {len(entries)} entries from HIPAA Journal")
        return entries

    # =========================================================================
    # HHS OCR BREACH PORTAL
    # =========================================================================
    def fetch_hhs_ocr(self, limit: int = 100) -> List[BreachEntry]:
        """Fetch from HHS OCR Breach Portal (HIPAA breaches)"""
        entries = []
        url = "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"

        logger.info("Fetching from HHS OCR...")
        response = self._safe_request(url)

        if not response:
            return entries

        try:
            # Use StringIO for pandas compatibility with newer versions
            tables = pd.read_html(StringIO(response.text))
            if len(tables) > 1:
                df = tables[1]  # Main breach table is usually index 1

                # The table may have an "Expand All" column with JS cruft - find the right columns
                # Map expected column names to potential variations
                col_map = {}
                for col in df.columns:
                    col_lower = str(col).lower()
                    if 'name of covered entity' in col_lower:
                        col_map['company'] = col
                    elif 'breach submission date' in col_lower:
                        col_map['date'] = col
                    elif 'individuals affected' in col_lower:
                        col_map['records'] = col
                    elif col_lower == 'state':
                        col_map['state'] = col
                    elif 'type of breach' in col_lower:
                        col_map['type'] = col

                for _, row in df.head(limit).iterrows():
                    entries.append(BreachEntry(
                        company_name=str(row.get(col_map.get('company', 'Name of Covered Entity'), 'Unknown')),
                        date_reported=str(row.get(col_map.get('date', 'Breach Submission Date'), '')),
                        source='HHS OCR',
                        url=url,
                        records_affected=str(row.get(col_map.get('records', 'Individuals Affected'), 'Unknown')),
                        location=str(row.get(col_map.get('state', 'State'), '')),
                        breach_type=str(row.get(col_map.get('type', 'Type of Breach'), 'Healthcare Breach'))
                    ))
            logger.info(f"Fetched {len(entries)} entries from HHS OCR")
        except Exception as e:
            logger.error(f"Failed to fetch HHS OCR: {e}")

        return entries

    # =========================================================================
    # CALIFORNIA AG
    # =========================================================================
    def fetch_california_ag(self, limit: int = 100) -> List[BreachEntry]:
        """Fetch from California AG breach list"""
        entries = []
        url = "https://oag.ca.gov/privacy/databreach/list"

        logger.info("Fetching from California AG...")
        response = self._safe_request(url)

        if not response:
            return entries

        try:
            # Use StringIO for pandas compatibility with newer versions
            tables = pd.read_html(StringIO(response.text))
            if tables:
                df = tables[0]
                for _, row in df.head(limit).iterrows():
                    entries.append(BreachEntry(
                        company_name=str(row.get('Organization Name', 'Unknown')),
                        date_reported=str(row.get('Reported Date', '')),
                        source='California AG',
                        url=url,
                        location='California',
                        breach_type='Data Breach'
                    ))
            logger.info(f"Fetched {len(entries)} entries from California AG")
        except Exception as e:
            logger.error(f"Failed to fetch California AG: {e}")

        return entries

    # =========================================================================
    # BLEEPING COMPUTER RSS
    # =========================================================================
    def fetch_bleeping_computer(self, limit: int = 30) -> List[BreachEntry]:
        """Fetch security news from BleepingComputer RSS"""
        entries = []
        url = "https://www.bleepingcomputer.com/feed/"
        
        logger.info("Fetching from BleepingComputer RSS...")
        
        keywords = ['breach', 'ransomware', 'hack', 'leak', 'attack', 'data stolen',
                   'cyberattack', 'compromised']
        
        try:
            feed = feedparser.parse(url)
            for item in feed.entries[:limit]:
                title_lower = item.get('title', '').lower()
                if any(kw in title_lower for kw in keywords):
                    description = ''
                    if hasattr(item, 'summary'):
                        soup = BeautifulSoup(item.summary, 'html.parser')
                        description = soup.get_text()[:500]
                    
                    entries.append(BreachEntry(
                        company_name=item.get('title', 'Unknown'),
                        date_reported=getattr(item, 'published', ''),
                        source='BleepingComputer',
                        url=item.get('link', ''),
                        description=description,
                        breach_type='Security News'
                    ))
            logger.info(f"Fetched {len(entries)} entries from BleepingComputer")
        except Exception as e:
            logger.warning(f"Failed to fetch BleepingComputer: {e}")

        return entries

    # =========================================================================
    # RED PACKET SECURITY RSS
    # =========================================================================
    def fetch_red_packet_security(self, limit: int = 50) -> List[BreachEntry]:
        """Fetch ransomware victim data from Red Packet Security RSS"""
        entries = []
        url = "https://www.redpacketsecurity.com/category/ransomware/feed/"

        logger.info("Fetching from Red Packet Security RSS...")

        try:
            feed = feedparser.parse(url)
            for item in feed.entries[:limit]:
                title = item.get('title', '')

                # Parse title format: "[GROUP] – Ransomware Victim: Company Name"
                threat_actor = ''
                company_name = title

                if title.startswith('[') and ']' in title:
                    bracket_end = title.index(']')
                    threat_actor = title[1:bracket_end].strip()
                    # Extract company name after "Ransomware Victim:"
                    if 'Ransomware Victim:' in title:
                        company_name = title.split('Ransomware Victim:')[-1].strip()
                    elif '–' in title:
                        company_name = title.split('–')[-1].strip()

                description = ''
                if hasattr(item, 'summary'):
                    soup = BeautifulSoup(item.summary, 'html.parser')
                    description = soup.get_text()[:500]

                entries.append(BreachEntry(
                    company_name=company_name,
                    date_reported=item.get('published', ''),
                    source='Red Packet Security',
                    url=item.get('link', ''),
                    description=description,
                    threat_actor=threat_actor,
                    breach_type='Ransomware'
                ))
            logger.info(f"Fetched {len(entries)} entries from Red Packet Security")
        except Exception as e:
            logger.warning(f"Failed to fetch Red Packet Security: {e}")

        return entries

    # =========================================================================
    # HENDRY ADRIAN RANSOM MONITOR
    # =========================================================================
    def _parse_hendry_adrian_post(self, post_url: str) -> Optional[Dict]:
        """Parse an individual Hendry Adrian post page for detailed metadata"""
        response = self._safe_request(post_url)
        if not response:
            return None

        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            data = {}

            # Find the main content area
            content = soup.find('div', class_='entry-content') or soup.find('article') or soup

            # Extract fields using <strong> labels pattern
            # Format: <strong>Label:</strong> value or <strong>Label:</strong> <a>value</a>
            text_content = content.get_text()

            # Actor - look for the link after "Actor:" label
            actor_link = content.find('a', href=lambda x: x and 'cse.google.com' in str(x) and 'q=' in str(x))
            if actor_link:
                data['actor'] = actor_link.get_text(strip=True)
            else:
                # Fallback: parse from text
                actor_match = re.search(r'Actor:\s*([^\n]+)', text_content)
                if actor_match:
                    data['actor'] = actor_match.group(1).strip()

            # Country - look for link to /ransom/id.php or hashtag pattern
            country_link = content.find('a', href=lambda x: x and '/ransom/id.php?id=' in str(x))
            if country_link:
                data['country'] = country_link.get_text(strip=True)
            else:
                # Try hashtag pattern like #UnitedStates
                hashtag_match = re.search(r'#([A-Z][a-zA-Z]+(?:[A-Z][a-zA-Z]+)*)', text_content)
                if hashtag_match:
                    # Convert CamelCase to spaces: UnitedStates -> United States
                    country = re.sub(r'([a-z])([A-Z])', r'\1 \2', hashtag_match.group(1))
                    data['country'] = country

            # Sector/Industry
            sector_match = re.search(r'Sector:\s*([^\n]+)', text_content)
            if sector_match:
                sector = sector_match.group(1).strip()
                if sector.lower() not in ['not found', 'n/a', 'unknown', '']:
                    data['sector'] = sector

            # Discovered date (more precise than published)
            discovered_match = re.search(r'Discovered:\s*(\d{4}-\d{2}-\d{2})', text_content)
            if discovered_match:
                data['discovered'] = discovered_match.group(1)

            # Get meta description for additional context
            meta_desc = soup.find('meta', {'name': 'description'})
            if meta_desc and meta_desc.get('content'):
                data['description'] = meta_desc['content'][:500]

            return data

        except Exception as e:
            logger.debug(f"Failed to parse Hendry Adrian post {post_url}: {e}")
            return None

    def fetch_hendry_adrian(self, limit: int = 50, fetch_details: bool = True) -> List[BreachEntry]:
        """Fetch from hendryadrian.com ransom monitor (WordPress)

        Args:
            limit: Maximum entries to return
            fetch_details: If True, fetch individual post pages for threat actor info
                          (slower but provides richer data)
        """
        entries = []
        url = "https://www.hendryadrian.com/ransom-monitor/"

        logger.info("Fetching from Hendry Adrian Ransom Monitor...")
        response = self._safe_request(url)

        if not response:
            return entries

        try:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find WordPress block post items
            post_titles = soup.find_all('h2', class_='wp-block-post-title')

            # Collect post URLs first
            posts_to_fetch = []
            for title_el in post_titles[:limit]:
                link = title_el.find('a')
                if not link:
                    continue

                full_title = link.get_text(strip=True)
                href = link.get('href', '')

                # Strip "Ransom! " prefix from title
                company_name = full_title
                if full_title.startswith('Ransom!'):
                    company_name = full_title.replace('Ransom!', '').strip()

                # Find associated date from listing page
                date_str = ''
                parent = title_el.find_parent(class_='wp-block-post')
                if parent:
                    time_el = parent.find('time')
                    if time_el:
                        date_str = time_el.get('datetime', time_el.get_text(strip=True))

                if company_name:
                    posts_to_fetch.append({
                        'company_name': company_name,
                        'url': href if href else url,
                        'date': date_str
                    })

            # Fetch individual post pages for detailed metadata
            # Limit detail fetches to avoid too many requests
            detail_limit = min(len(posts_to_fetch), 25) if fetch_details else 0

            for i, post in enumerate(posts_to_fetch):
                threat_actor = ''
                location = ''
                description = ''
                date_reported = post['date']

                # Fetch detailed info for first N posts
                if i < detail_limit and post['url'].startswith('http'):
                    details = self._parse_hendry_adrian_post(post['url'])
                    if details:
                        threat_actor = details.get('actor', '')
                        location = details.get('country', '')
                        description = details.get('description', '')
                        # Use discovered date if available (more accurate)
                        if details.get('discovered'):
                            date_reported = details['discovered']
                    # Small delay to be respectful to the server
                    time.sleep(0.3)

                entries.append(BreachEntry(
                    company_name=post['company_name'],
                    date_reported=date_reported,
                    source='Hendry Adrian',
                    url=post['url'],
                    description=description,
                    location=location,
                    threat_actor=threat_actor,
                    breach_type='Ransomware'
                ))

            logger.info(f"Fetched {len(entries)} entries from Hendry Adrian ({detail_limit} with details)")
        except Exception as e:
            logger.warning(f"Failed to fetch Hendry Adrian: {e}")

        return entries

    # =========================================================================
    # DEXPOSE INTEL FEEDS
    # =========================================================================
    def fetch_dexpose(self, limit: int = 50) -> List[BreachEntry]:
        """Fetch from dexpose.io intel feeds"""
        entries = []
        url = "https://www.dexpose.io/intel-feeds/"

        logger.info("Fetching from DeXpose Intel Feeds...")
        response = self._safe_request(url)

        if not response:
            return entries

        try:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Known threat actor tags to look for
            known_actors = [
                'qilin', 'akira', 'lockbit', 'blackcat', 'alphv', 'clop', 'play',
                'bianlian', 'medusa', 'rhysida', 'hunters', 'ransomhub', '8base',
                'cactus', 'blackbasta', 'royal', 'vice', 'snatch', 'ragnar',
                'payoutsking', 'conti', 'hive', 'revil', 'darkside', 'avaddon'
            ]

            # Find grid items with post class
            grid_items = soup.find_all(class_=lambda x: x and 'w-grid-item' in str(x) and 'post' in str(x))

            for item in grid_items[:limit]:
                classes = item.get('class', [])

                # Extract threat actor from CSS classes (tags)
                threat_actor = ''
                for cls in classes:
                    if cls.startswith('tag-'):
                        tag = cls.replace('tag-', '').lower()
                        if tag in known_actors:
                            threat_actor = tag.title()
                            break

                # Get title and link
                title_el = item.find(class_='w-post-elm-title')
                if not title_el:
                    title_el = item.find(['h2', 'h3', 'h4'])

                if not title_el:
                    continue

                link = title_el.find('a')
                title = (link.get_text(strip=True) if link else title_el.get_text(strip=True))
                href = link.get('href', '') if link else ''

                # Get date
                date_str = ''
                time_el = item.find('time')
                if time_el:
                    date_str = time_el.get('datetime', time_el.get_text(strip=True))

                # Get excerpt/description
                description = ''
                excerpt_el = item.find(class_='w-post-elm-content')
                if excerpt_el:
                    description = excerpt_el.get_text(strip=True)[:500]

                if title:
                    entries.append(BreachEntry(
                        company_name=title,
                        date_reported=date_str,
                        source='DeXpose',
                        url=href if href else url,
                        description=description,
                        threat_actor=threat_actor,
                        breach_type='Ransomware'
                    ))

            logger.info(f"Fetched {len(entries)} entries from DeXpose")
        except Exception as e:
            logger.warning(f"Failed to fetch DeXpose: {e}")

        return entries

    # =========================================================================
    # SECURITY NEWS RSS FEEDS
    # =========================================================================

    # Configurable list of security news RSS feeds
    NEWS_FEEDS = [
        # Cybersecurity News
        ('Krebs on Security', 'https://krebsonsecurity.com/feed/', 'News'),
        ('The Record', 'https://therecord.media/feed/', 'News'),
        ('The Hacker News', 'https://feeds.feedburner.com/TheHackernews', 'News'),
        ('SecurityWeek', 'https://feeds.feedburner.com/securityweek', 'News'),
        ('Dark Reading', 'https://www.darkreading.com/rss.xml', 'News'),
        ('CyberScoop', 'https://www.cyberscoop.com/feed', 'News'),
        ('SC Media', 'https://www.scworld.com/feed', 'News'),
        ('Security Affairs', 'https://securityaffairs.com/feed', 'News'),
        ('HackRead', 'https://hackread.com/feed/', 'News'),
        ('Cyble', 'https://cyble.com/feed/', 'Threat Intel'),
        ('WeLiveSecurity', 'https://www.welivesecurity.com/en/feed/', 'News'),
        ('Graham Cluley', 'https://grahamcluley.com/feed/', 'News'),
        ('Tripwire', 'https://www.tripwire.com/state-of-security/feed', 'News'),
        # Healthcare/Finance
        ('DataBreachToday', 'https://www.databreachtoday.com/rssFeeds.php', 'Healthcare'),
        ('BankInfoSecurity', 'https://www.bankinfosecurity.com/rss-feeds', 'Finance'),
        # Vendor/Research
        ('Sophos News', 'https://news.sophos.com/en-us/feed/', 'Threat Intel'),
        ('Kaspersky Securelist', 'https://securelist.com/feed/', 'Threat Intel'),
        ('SentinelOne Labs', 'https://www.sentinelone.com/feed/', 'Threat Intel'),
        ('Malwarebytes Blog', 'https://www.malwarebytes.com/blog/feed', 'Threat Intel'),
    ]

    def fetch_security_news_feed(self, source_name: str, feed_url: str,
                                  category: str, limit: int = 20) -> List[BreachEntry]:
        """Generic fetcher for security news RSS feeds"""
        entries = []

        try:
            feed = feedparser.parse(feed_url)
            for item in feed.entries[:limit]:
                title = item.get('title', '').lower()

                # Filter for breach/security related content
                keywords = ['breach', 'ransomware', 'hack', 'leak', 'attack', 'data',
                           'malware', 'phishing', 'vulnerability', 'exploit', 'threat',
                           'cyber', 'security', 'compromise', 'stolen', 'exposed']

                if any(kw in title for kw in keywords):
                    description = ''
                    if hasattr(item, 'summary'):
                        soup = BeautifulSoup(item.summary, 'html.parser')
                        description = soup.get_text()[:500]

                    entries.append(BreachEntry(
                        company_name=item.get('title', 'Unknown'),
                        date_reported=item.get('published', item.get('updated', '')),
                        source=source_name,
                        url=item.get('link', ''),
                        description=description,
                        breach_type=category
                    ))
        except Exception as e:
            logger.warning(f"Failed to fetch {source_name}: {e}")

        return entries

    def fetch_all_news_feeds(self, limit_per_feed: int = 20) -> List[BreachEntry]:
        """Fetch from all configured security news RSS feeds"""
        all_entries = []

        for source_name, feed_url, category in self.NEWS_FEEDS:
            logger.info(f"Fetching from {source_name}...")
            entries = self.fetch_security_news_feed(source_name, feed_url, category, limit_per_feed)
            all_entries.extend(entries)
            logger.info(f"Fetched {len(entries)} entries from {source_name}")

        return all_entries

    # =========================================================================
    # STATE REGISTRIES (SELENIUM REQUIRED)
    # =========================================================================

    def fetch_maine_ag(self, limit: int = 20) -> List[BreachEntry]:
        """Fetch from Maine AG (requires Selenium)"""
        if not self.use_selenium:
            logger.info("Skipping Maine AG (Selenium disabled)")
            return []

        entries = []
        driver = None
        base_url = 'https://www.maine.gov/agviewer/content/ag/985235c7-cb95-4be2-8792-a1252b4f8318/'
        uuid_pattern = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\.s?html$')

        try:
            driver = create_chrome_driver()
            if not driver:
                return entries

            logger.info("Fetching from Maine AG (Selenium)...")
            driver.get(base_url + 'list.html')
            time.sleep(3)

            # Gather URLs - look for links with UUID pattern (site now uses relative URLs)
            urls = []
            for link in driver.find_elements(By.TAG_NAME, 'a'):
                href = link.get_attribute("href")
                if not href:
                    continue
                # Check for full URL with UUID or relative UUID path
                if uuid_pattern.search(href.split('/')[-1] if '/' in href else href):
                    # Ensure we have the full URL
                    if not href.startswith('http'):
                        href = base_url + href
                    urls.append(href)
            
            # Visit each URL
            for url in urls[:limit]:
                try:
                    driver.get(url)
                    time.sleep(1)
                    
                    content = driver.find_element(By.XPATH, '//*[@id="content"]').text
                    lines = [i for i in content.split("\n") if ": " in i]
                    
                    data_dict = {}
                    for line in lines:
                        if ': ' in line:
                            key, value = line.split(': ', 1)
                            data_dict[key.strip()] = value.strip()
                    
                    company_name = data_dict.get('Entity Name', 'Unknown')
                    total_affected = data_dict.get('Total number of persons affected (including residents)', 'N/A')
                    state_affected = data_dict.get('Total number of Maine residents affected', 'N/A')
                    date_reported = data_dict.get('Date(s) of consumer notification',
                                                 data_dict.get('Date Breach Discovered', ''))
                    
                    city = data_dict.get('City', '')
                    state = data_dict.get('State, or Country if outside the US', '')
                    location = f"{city}, {state}".strip(', ') if city or state else 'N/A'
                    
                    entries.append(BreachEntry(
                        company_name=company_name,
                        date_reported=date_reported,
                        source='Maine AG',
                        url=url,
                        records_affected=total_affected,
                        state_records_affected=state_affected,
                        location=location,
                        breach_type='State Registry'
                    ))
                except Exception:
                    continue
            
            logger.info(f"Fetched {len(entries)} entries from Maine AG")
            
        except Exception as e:
            logger.error(f"Failed to fetch Maine AG: {e}")
        finally:
            if driver:
                driver.quit()
        
        return entries

    def fetch_texas_ag(self, limit: int = 50) -> List[BreachEntry]:
        """Fetch from Texas AG (requires Selenium)"""
        if not self.use_selenium:
            logger.info("Skipping Texas AG (Selenium disabled)")
            return []

        entries = []
        driver = None

        try:
            driver = create_chrome_driver()
            if not driver:
                return entries

            logger.info("Fetching from Texas AG (Selenium)...")
            driver.get('https://oag.my.site.com/datasecuritybreachreport/apex/DataSecurityReportsPage')

            # Wait for the DataTable to be initialized and data to load via Visualforce remoting
            wait = WebDriverWait(driver, 20)

            # Wait for the table body to have data rows (Visualforce loads data async)
            wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, '#mycdrs tbody tr td')))
            time.sleep(2)  # Additional wait for full data population

            # Click the date column header to sort descending (newest first)
            # The date column is index 9 (0-based), find it in the header
            try:
                date_header = wait.until(EC.element_to_be_clickable(
                    (By.XPATH, '//table[@id="mycdrs"]//th[contains(text(),"Date Published")]')
                ))
                # Click twice to sort descending (default is ascending)
                date_header.click()
                time.sleep(1)
                date_header.click()
                time.sleep(1)
            except TimeoutException:
                # Fallback: try clicking last page if header click fails
                try:
                    last_button = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, '#mycdrs_last')))
                    last_button.click()
                    time.sleep(2)
                except Exception:
                    logger.warning("Could not navigate to recent entries in Texas AG")

            # Parse the table using pandas
            tables = pd.read_html(StringIO(driver.page_source))
            if not tables:
                logger.warning("No tables found in Texas AG page")
                return entries

            # Find the table with the expected columns
            df = None
            for table in tables:
                if 'Entity or Individual Name' in table.columns or len(table.columns) >= 9:
                    df = table
                    break

            if df is None:
                df = tables[0]

            for _, row in df.head(limit).iterrows():
                city = row.get('Entity or Individual City', '')
                state = row.get('Entity or Individual State', '')
                location = f"{city}, {state}".strip(', ') if city or state else 'Texas'

                entries.append(BreachEntry(
                    company_name=str(row.get('Entity or Individual Name', 'Unknown')),
                    date_reported=str(row.get('Date Published at OAG Website', '')),
                    source='Texas AG',
                    url='https://oag.my.site.com/datasecuritybreachreport/apex/DataSecurityReportsPage',
                    state_records_affected=str(row.get('Number of Texans Affected', 'N/A')),
                    location=location,
                    breach_type='State Registry'
                ))

            logger.info(f"Fetched {len(entries)} entries from Texas AG")

        except Exception as e:
            logger.error(f"Failed to fetch Texas AG: {e}")
        finally:
            if driver:
                driver.quit()

        return entries

    def fetch_washington_ag(self, limit: int = 50) -> List[BreachEntry]:
        """Fetch from Washington AG (requires Selenium)"""
        if not self.use_selenium:
            logger.info("Skipping Washington AG (Selenium disabled)")
            return []
        
        entries = []
        driver = None
        
        try:
            driver = create_chrome_driver()
            if not driver:
                return entries
            
            logger.info("Fetching from Washington AG (Selenium)...")
            driver.get("https://www.atg.wa.gov/data-breach-notifications")
            time.sleep(3)
            
            df = pd.read_html(StringIO(driver.page_source))[0]

            for _, row in df.head(limit).iterrows():
                try:
                    first_col = str(row[0]) if 0 in row.index else str(row.iloc[0])
                    
                    org_name = 'Unknown'
                    if 'Organization Name' in first_col:
                        org_name = first_col.split('Organization Name')[-1].split('\n')[0].strip()
                    
                    date_reported = ''
                    wa_affected = 'N/A'
                    
                    for col_val in row.values:
                        col_str = str(col_val)
                        if 'Date Reported' in col_str:
                            date_reported = col_str.split('Date Reported')[-1].split('\n')[0].strip()
                        if 'Number of Washingtonians Affected' in col_str:
                            wa_affected = col_str.split('Number of Washingtonians Affected')[-1].split('\n')[0].strip()
                    
                    entries.append(BreachEntry(
                        company_name=org_name,
                        date_reported=date_reported,
                        source='Washington AG',
                        url='https://www.atg.wa.gov/data-breach-notifications',
                        state_records_affected=wa_affected,
                        location='Washington',
                        breach_type='State Registry'
                    ))
                except Exception:
                    continue
            
            logger.info(f"Fetched {len(entries)} entries from Washington AG")
            
        except Exception as e:
            logger.error(f"Failed to fetch Washington AG: {e}")
        finally:
            if driver:
                driver.quit()
        
        return entries

    # =========================================================================
    # RESCANA BLOG (SELENIUM REQUIRED - Wix site)
    # =========================================================================
    def fetch_rescana_blog(self, limit: int = 20) -> List[BreachEntry]:
        """Fetch from Rescana blog (requires Selenium - Wix site)"""
        if not self.use_selenium:
            logger.info("Skipping Rescana blog (Selenium disabled)")
            return []

        entries = []
        driver = None

        try:
            driver = create_chrome_driver()
            if not driver:
                return entries

            logger.info("Fetching from Rescana blog (Selenium)...")
            driver.get("https://www.rescana.com/blog")
            time.sleep(5)  # Wait for Wix dynamic content to load

            # Scroll to load more content
            driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
            time.sleep(2)

            # Find blog post elements - Wix typically uses data-testid or specific class patterns
            posts = driver.find_elements(By.CSS_SELECTOR, '[data-testid="richTextElement"], .blog-post-title, h2 a, [data-hook="post-title"]')

            if not posts:
                # Try alternative selectors for Wix blogs
                posts = driver.find_elements(By.XPATH, '//a[contains(@href, "/post/")]')

            seen_urls = set()
            for post in posts[:limit * 2]:  # Get more to filter duplicates
                try:
                    href = post.get_attribute('href')
                    if not href or '/post/' not in href or href in seen_urls:
                        continue
                    seen_urls.add(href)

                    title = post.text.strip() or post.get_attribute('title') or ''
                    if not title:
                        title = href.split('/post/')[-1].replace('-', ' ').title()

                    # Filter for security-related content
                    title_lower = title.lower()
                    keywords = ['breach', 'ransomware', 'hack', 'cyber', 'attack', 'security',
                               'threat', 'vulnerability', 'malware', 'data', 'incident']
                    if any(kw in title_lower for kw in keywords):
                        # Try to get date from post page or parent element
                        post_date = ''
                        try:
                            parent = post.find_element(By.XPATH, './ancestor::article | ./ancestor::div[contains(@class, "post")]')
                            parent_text = parent.text
                            # Look for common date patterns
                            date_patterns = [
                                r'(\d{1,2}/\d{1,2}/\d{2,4})',
                                r'(\w+ \d{1,2},? \d{4})',
                                r'(\d{4}-\d{2}-\d{2})',
                            ]
                            for pattern in date_patterns:
                                match = re.search(pattern, parent_text)
                                if match:
                                    post_date = match.group(1)
                                    break
                        except Exception:
                            pass

                        entries.append(BreachEntry(
                            company_name=title,
                            date_reported=post_date,  # Empty string if not found - will be handled by _parse_date
                            source='Rescana',
                            url=href,
                            description='',
                            breach_type='Threat Intel'
                        ))

                    if len(entries) >= limit:
                        break
                except Exception:
                    continue

            logger.info(f"Fetched {len(entries)} entries from Rescana blog")

        except Exception as e:
            logger.error(f"Failed to fetch Rescana blog: {e}")
        finally:
            if driver:
                driver.quit()

        return entries

    # =========================================================================
    # MAIN COLLECTION
    # =========================================================================

    def collect_all(self, parallel: bool = True, include_selenium: bool = True,
                     max_per_source: int = 25) -> List[BreachEntry]:
        """Collect from all sources

        Args:
            parallel: Run basic sources in parallel
            include_selenium: Include Selenium-based sources
            max_per_source: Maximum entries per source to ensure balanced feed (0 = no limit)
        """
        all_entries = []

        # API and RSS sources (no Selenium needed)
        basic_sources = [
            ('ransomware.live', self.fetch_ransomware_live),
            ('databreaches.net', self.fetch_databreaches_net),
            ('breachsense.com', self.fetch_breachsense),
            ('HIPAA Journal', self.fetch_hipaa_journal),
            ('HHS OCR', self.fetch_hhs_ocr),
            ('California AG', self.fetch_california_ag),
            ('BleepingComputer', self.fetch_bleeping_computer),
            ('Red Packet Security', self.fetch_red_packet_security),
            ('Hendry Adrian', self.fetch_hendry_adrian),
            ('DeXpose', self.fetch_dexpose),
            ('Security News Feeds', self.fetch_all_news_feeds),
        ]

        # Selenium sources (run sequentially to avoid browser conflicts)
        selenium_sources = [
            ('Maine AG', self.fetch_maine_ag),
            ('Texas AG', self.fetch_texas_ag),
            ('Washington AG', self.fetch_washington_ag),
            ('Rescana', self.fetch_rescana_blog),
        ]

        def cap_entries(entries: List[BreachEntry], source: str) -> List[BreachEntry]:
            """Apply per-source cap if configured"""
            if max_per_source > 0 and len(entries) > max_per_source:
                logger.info(f"  Capping {source} from {len(entries)} to {max_per_source} entries")
                return entries[:max_per_source]
            return entries

        # Fetch basic sources (can be parallel)
        if parallel:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(func): name for name, func in basic_sources}
                for future in as_completed(futures):
                    source_name = futures[future]
                    try:
                        entries = future.result()
                        entries = cap_entries(entries, source_name)
                        all_entries.extend(entries)
                        logger.info(f"✓ {source_name}: {len(entries)} entries")
                    except Exception as e:
                        logger.error(f"✗ {source_name} failed: {e}")
        else:
            for name, func in basic_sources:
                try:
                    entries = func()
                    entries = cap_entries(entries, name)
                    all_entries.extend(entries)
                    logger.info(f"✓ {name}: {len(entries)} entries")
                except Exception as e:
                    logger.error(f"✗ {name} failed: {e}")

        # Fetch Selenium sources sequentially
        if include_selenium and self.use_selenium:
            for name, func in selenium_sources:
                try:
                    entries = func()
                    entries = cap_entries(entries, name)
                    all_entries.extend(entries)
                    logger.info(f"✓ {name}: {len(entries)} entries")
                except Exception as e:
                    logger.error(f"✗ {name} failed: {e}")

        # Deduplicate by case_id (one entry per breach case across all sources)
        case_entries: Dict[str, BreachEntry] = {}
        for entry in all_entries:
            case_key = entry.case_id
            if case_key not in case_entries:
                case_entries[case_key] = entry
            else:
                # Merge information from duplicate entries
                existing = case_entries[case_key]

                # Merge sources (comma-separated list of unique sources)
                existing_sources = set(s.strip() for s in existing.source.split(','))
                existing_sources.add(entry.source)
                existing.source = ', '.join(sorted(existing_sources))

                # Prefer non-empty values for optional fields
                if not existing.threat_actor and entry.threat_actor:
                    existing.threat_actor = entry.threat_actor
                if not existing.description and entry.description:
                    existing.description = entry.description
                if existing.records_affected in ['Unknown', 'N/A', ''] and entry.records_affected not in ['Unknown', 'N/A', '']:
                    existing.records_affected = entry.records_affected
                if not existing.location and entry.location:
                    existing.location = entry.location

        unique_entries = list(case_entries.values())
        logger.info(f"Total unique cases: {len(unique_entries)} (from {len(all_entries)} raw entries)")
        return unique_entries


# =============================================================================
# RSS FEED GENERATOR
# =============================================================================

class RSSFeedGenerator:
    """Generate RSS/Atom feeds from breach entries"""
    
    def __init__(self, 
                 title: str = "Data Breach & Ransomware Feed",
                 link: str = "https://example.com/breaches",
                 description: str = "Aggregated data breach notifications"):
        self.fg = FeedGenerator()
        self.fg.title(title)
        self.fg.link(href=link, rel='alternate')
        self.fg.description(description)
        self.fg.language('en')
        self.fg.lastBuildDate(datetime.now(timezone.utc))
        self.fg.generator('Breach RSS Generator')
        
    def add_entries(self, entries: List[BreachEntry]):
        """Add breach entries to the feed"""
        for entry in entries:
            fe = self.fg.add_entry()
            fe.id(entry.unique_id)
            fe.title(entry.company_name)

            # Validate URL - must start with http
            url = entry.url if entry.url.startswith('http') else f"https://www.google.com/search?q={entry.company_name.replace(' ', '+')}+data+breach"
            fe.link(href=url)
            
            # Build description with better formatting
            desc_parts = []

            # Lead with narrative description if available
            if entry.description:
                desc_parts.append(entry.description)
            else:
                # Generate a readable summary for entries without descriptions
                summary = f"{entry.company_name} reported a {entry.breach_type.lower()}"
                if entry.records_affected and entry.records_affected not in ['Unknown', 'N/A', '']:
                    summary += f" affecting {entry.records_affected} records"
                if entry.location:
                    summary += f" in {entry.location}"
                if entry.threat_actor:
                    summary += f". Attributed to {entry.threat_actor}"
                summary += "."
                desc_parts.append(summary)

            # Add structured metadata
            metadata = []
            if entry.threat_actor:
                metadata.append(f"🎭 Threat Actor: {entry.threat_actor}")
            if entry.records_affected and entry.records_affected not in ['Unknown', 'N/A', '']:
                metadata.append(f"📊 Records Affected: {entry.records_affected}")
            if entry.location:
                metadata.append(f"📍 Location: {entry.location}")
            metadata.append(f"📰 Source: {entry.source}")
            metadata.append(f"🏷️ Type: {entry.breach_type}")

            if metadata:
                desc_parts.append("\n" + " | ".join(metadata))
            
            fe.description('\n'.join(desc_parts))
            
            # Parse and set date
            pub_date = self._parse_date(entry.date_reported)
            fe.pubDate(pub_date)
            
            # Add categories
            fe.category(term=entry.breach_type)
            fe.category(term=entry.source)
            if entry.threat_actor:
                fe.category(term=f"Actor: {entry.threat_actor}")
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime with timezone"""
        if not date_str:
            logger.debug("Empty date string, using current time")
            return datetime.now(timezone.utc)

        # Clean up the date string
        clean_date = date_str.strip()
        # Remove microseconds if present (common in API responses)
        if '.' in clean_date and len(clean_date.split('.')[-1]) > 4:
            clean_date = clean_date.split('.')[0]

        formats = [
            '%Y-%m-%d %H:%M:%S.%f',  # With microseconds
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S.%f',  # ISO with microseconds
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S%z',
            '%a, %d %b %Y %H:%M:%S %z',
            '%a, %d %b %Y %H:%M:%S %Z',
            '%a, %d %b %Y %H:%M:%S GMT',
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%m/%d/%y',
            '%B %d, %Y',
            '%b %d, %Y',
            '%b %d %Y',
            '%b %d, %Y',  # Jan 5, 2024
            '%d %b %Y',   # 5 Jan 2024
            '%d %B %Y',   # 5 January 2024
        ]

        for fmt in formats:
            try:
                parsed = datetime.strptime(clean_date, fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                continue

        # Try parsing with dateutil as a fallback
        try:
            from dateutil import parser as dateutil_parser
            parsed = dateutil_parser.parse(clean_date)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except Exception:
            pass

        logger.warning(f"Could not parse date '{date_str}', using current time")
        return datetime.now(timezone.utc)
    
    def generate_rss(self) -> str:
        return self.fg.rss_str(pretty=True).decode('utf-8')
    
    def generate_atom(self) -> str:
        return self.fg.atom_str(pretty=True).decode('utf-8')
    
    def save_rss(self, filepath: str):
        self.fg.rss_file(filepath)
        logger.info(f"RSS feed saved to {filepath}")
    
    def save_atom(self, filepath: str):
        self.fg.atom_file(filepath)
        logger.info(f"Atom feed saved to {filepath}")


# =============================================================================
# FLASK SERVER (OPTIONAL)
# =============================================================================

def create_flask_app(collector: BreachDataCollector):
    """Create Flask app to serve the RSS feed"""
    try:
        from flask import Flask, Response, jsonify
    except ImportError:
        logger.error("Flask not installed. Run: pip install flask")
        return None
    
    app = Flask(__name__)
    cache = {'entries': [], 'last_update': None}
    
    def update_cache():
        cache['entries'] = collector.collect_all(include_selenium=False)
        cache['last_update'] = datetime.now(timezone.utc)
    
    @app.route('/')
    def index():
        return """
        <h1>Data Breach RSS Feed</h1>
        <ul>
            <li><a href="/rss">RSS Feed</a></li>
            <li><a href="/atom">Atom Feed</a></li>
            <li><a href="/json">JSON Data</a></li>
            <li><a href="/refresh">Refresh Data</a></li>
        </ul>
        """
    
    @app.route('/rss')
    def rss():
        if not cache['entries'] or not cache['last_update'] or \
           (datetime.now(timezone.utc) - cache['last_update']).total_seconds() > 3600:
            update_cache()
        
        feed_gen = RSSFeedGenerator()
        feed_gen.add_entries(cache['entries'])
        return Response(feed_gen.generate_rss(), mimetype='application/rss+xml')
    
    @app.route('/atom')
    def atom():
        if not cache['entries'] or not cache['last_update'] or \
           (datetime.now(timezone.utc) - cache['last_update']).total_seconds() > 3600:
            update_cache()
        
        feed_gen = RSSFeedGenerator()
        feed_gen.add_entries(cache['entries'])
        return Response(feed_gen.generate_atom(), mimetype='application/atom+xml')
    
    @app.route('/json')
    def json_data():
        if not cache['entries'] or not cache['last_update'] or \
           (datetime.now(timezone.utc) - cache['last_update']).total_seconds() > 3600:
            update_cache()
        
        return jsonify([e.to_dict() for e in cache['entries']])
    
    @app.route('/refresh')
    def refresh():
        update_cache()
        return jsonify({
            'status': 'ok',
            'entries': len(cache['entries']),
            'updated': cache['last_update'].isoformat()
        })
    
    return app


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Generate RSS feed from data breach sources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate RSS feed
  python breach_rss_full.py -o breaches.xml
  
  # Generate RSS + JSON + CSV
  python breach_rss_full.py -o breaches.xml --json breaches.json --csv breaches.csv
  
  # Run as web server
  python breach_rss_full.py --serve --port 8080
  
  # Skip Selenium-based sources
  python breach_rss_full.py -o breaches.xml --no-selenium
        """
    )
    parser.add_argument('--output', '-o', default='breaches.xml', help='Output RSS file path')
    parser.add_argument('--format', '-f', choices=['rss', 'atom', 'both'], default='rss')
    parser.add_argument('--json', '-j', help='Also save as JSON')
    parser.add_argument('--csv', '-c', help='Also save as CSV')
    parser.add_argument('--no-parallel', action='store_true', help='Disable parallel fetching')
    parser.add_argument('--no-selenium', action='store_true', help='Skip Selenium-based sources')
    parser.add_argument('--max-per-source', type=int, default=25, help='Max entries per source for balanced feed (0=unlimited)')
    parser.add_argument('--serve', action='store_true', help='Run as Flask web server')
    parser.add_argument('--port', type=int, default=5000, help='Port for Flask server')
    args = parser.parse_args()
    
    # Create collector
    collector = BreachDataCollector(use_selenium=not args.no_selenium)
    
    # Run as server
    if args.serve:
        app = create_flask_app(collector)
        if app:
            print(f"Starting server on http://localhost:{args.port}")
            print(f"  RSS:  http://localhost:{args.port}/rss")
            print(f"  Atom: http://localhost:{args.port}/atom")
            print(f"  JSON: http://localhost:{args.port}/json")
            app.run(host='0.0.0.0', port=args.port, debug=False)
        return
    
    # Collect data
    entries = collector.collect_all(
        parallel=not args.no_parallel,
        include_selenium=not args.no_selenium,
        max_per_source=args.max_per_source
    )
    
    # Sort by date (newest first)
    def get_sort_date(e):
        try:
            for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%B %d, %Y']:
                try:
                    return datetime.strptime(e.date_reported[:10], fmt)
                except:
                    continue
        except:
            pass
        return datetime.min
    
    entries.sort(key=get_sort_date, reverse=True)
    
    # Generate feed
    feed_gen = RSSFeedGenerator(
        title="Data Breach & Ransomware Aggregator",
        link="https://example.com/breach-feed",
        description="Real-time data breach notifications from state registries, federal sources, and ransomware trackers"
    )
    feed_gen.add_entries(entries)
    
    # Save outputs
    if args.format in ['rss', 'both']:
        rss_path = args.output if args.output.endswith('.xml') else f"{args.output}.rss.xml"
        feed_gen.save_rss(rss_path)
    
    if args.format in ['atom', 'both']:
        atom_path = args.output.replace('.xml', '.atom.xml') if '.xml' in args.output else f"{args.output}.atom.xml"
        feed_gen.save_atom(atom_path)
    
    if args.json:
        with open(args.json, 'w') as f:
            json.dump([e.to_dict() for e in entries], f, indent=2)
        logger.info(f"JSON saved to {args.json}")
    
    if args.csv:
        df = pd.DataFrame([e.to_dict() for e in entries])
        df.to_csv(args.csv, index=False)
        logger.info(f"CSV saved to {args.csv}")
    
    # Summary
    print(f"\n{'='*60}")
    print(f"Generated feed with {len(entries)} entries")
    print(f"{'='*60}")
    
    from collections import Counter
    source_counts = Counter(e.source for e in entries)
    print("\nEntries by source:")
    for source, count in source_counts.most_common():
        print(f"  {source}: {count}")
    
    type_counts = Counter(e.breach_type for e in entries)
    print("\nEntries by type:")
    for btype, count in type_counts.most_common():
        print(f"  {btype}: {count}")


if __name__ == '__main__':
    main()
