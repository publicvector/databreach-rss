#!/usr/bin/env python3
"""
Data Breach RSS Feed Generator - Full Version

Aggregates data breach notifications from:

STATE REGISTRIES (require Selenium):
- Maine AG
- Texas AG  
- Washington AG
- Hawaii DCCA
- California AG

FEDERAL SOURCES:
- HHS OCR (HIPAA breaches)

RANSOMWARE TRACKERS:
- ransomware.live API
- breachsense.com

NEWS SOURCES (RSS):
- databreaches.net
- HIPAA Journal
- BleepingComputer

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
        """Generate unique ID for deduplication"""
        # Normalize company name for better deduplication
        normalized_name = re.sub(r'[^\w\s]', '', self.company_name.lower())
        content = f"{normalized_name}{self.date_reported[:10] if len(self.date_reported) > 10 else self.date_reported}{self.source}"
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
    def fetch_ransomware_live(self, limit: int = 100) -> List[BreachEntry]:
        """Fetch recent victims from ransomware.live API (free, no auth)"""
        entries = []
        url = "https://api.ransomware.live/v2/recentvictims"
        
        logger.info("Fetching from ransomware.live API...")
        response = self._safe_request(url)
        
        if not response:
            return entries
        
        try:
            data = response.json()
            for victim in data[:limit]:
                # Handle nested group info
                group_name = victim.get('group_name', '')
                if not group_name and 'group' in victim:
                    group_name = victim['group'] if isinstance(victim['group'], str) else victim['group'].get('name', '')
                
                entries.append(BreachEntry(
                    company_name=victim.get('victim', 'Unknown'),
                    date_reported=victim.get('published', victim.get('discovered', '')),
                    source='Ransomware.live',
                    url=f"https://www.ransomware.live/search?query={victim.get('victim', '')}",
                    description=victim.get('activity', victim.get('description', ''))[:500],
                    location=victim.get('country', ''),
                    threat_actor=group_name,
                    breach_type='Ransomware'
                ))
            logger.info(f"Fetched {len(entries)} entries from ransomware.live")
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
                date_str = datetime.now().strftime('%Y-%m-%d')
                
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
                    
                    # Extract date
                    date_match = re.search(
                        r'((?:Dec|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov)\s+\d{1,2},?\s*\d{4})',
                        text
                    )
                    if date_match:
                        date_str = date_match.group(1)
                
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
            tables = pd.read_html(response.text)
            if len(tables) > 1:
                df = tables[1]  # Main breach table is usually index 1
                for _, row in df.head(limit).iterrows():
                    entries.append(BreachEntry(
                        company_name=str(row.get('Name of Covered Entity', 'Unknown')),
                        date_reported=str(row.get('Breach Submission Date', '')),
                        source='HHS OCR',
                        url=url,
                        records_affected=str(row.get('Individuals Affected', 'Unknown')),
                        location=str(row.get('State', '')),
                        breach_type=str(row.get('Type of Breach', 'Healthcare Breach'))
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
            tables = pd.read_html(response.text)
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
    # STATE REGISTRIES (SELENIUM REQUIRED)
    # =========================================================================
    
    def fetch_maine_ag(self, limit: int = 20) -> List[BreachEntry]:
        """Fetch from Maine AG (requires Selenium)"""
        if not self.use_selenium:
            logger.info("Skipping Maine AG (Selenium disabled)")
            return []
        
        entries = []
        driver = None
        
        try:
            driver = create_chrome_driver()
            if not driver:
                return entries
            
            logger.info("Fetching from Maine AG (Selenium)...")
            driver.get('https://www.maine.gov/agviewer/content/ag/985235c7-cb95-4be2-8792-a1252b4f8318/list.html')
            time.sleep(3)
            
            # Gather URLs
            urls = []
            for link in driver.find_elements(By.TAG_NAME, 'a'):
                href = link.get_attribute("href")
                if href and len(str(href)) > 100:
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
            
            # Wait and click last page to get recent entries
            wait = WebDriverWait(driver, 10)
            last_button = wait.until(EC.element_to_be_clickable((By.XPATH, '//*[@id="mycdrs_last"]')))
            last_button.click()
            time.sleep(2)
            
            df = pd.read_html(driver.page_source)[0]
            
            for _, row in df.head(limit).iterrows():
                location = f"{row.get('Entity or Individual City', '')}, {row.get('Entity or Individual State', '')}".strip(', ')
                
                entries.append(BreachEntry(
                    company_name=str(row.get('Entity or Individual Name', 'Unknown')),
                    date_reported=str(row.get('Date Published at OAG Website', '')),
                    source='Texas AG',
                    url='https://oag.my.site.com/datasecuritybreachreport/apex/DataSecurityReportsPage',
                    state_records_affected=str(row.get('Number of Texans Affected', 'N/A')),
                    location=location or 'Texas',
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
            
            df = pd.read_html(driver.page_source)[0]
            
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

    def fetch_hawaii_dcca(self, limit: int = 50) -> List[BreachEntry]:
        """Fetch from Hawaii DCCA (requires Selenium)"""
        if not self.use_selenium:
            logger.info("Skipping Hawaii DCCA (Selenium disabled)")
            return []
        
        entries = []
        driver = None
        
        try:
            driver = create_chrome_driver()
            if not driver:
                return entries
            
            logger.info("Fetching from Hawaii DCCA (Selenium)...")
            driver.get("https://cca.hawaii.gov/ocp/notices/security-breach/")
            time.sleep(3)
            
            df = pd.read_html(driver.page_source)[0]
            
            for _, row in df.head(limit).iterrows():
                # Validate URL - use fallback if invalid
                raw_url = str(row.get('Link to Letter', ''))
                if raw_url.startswith('http'):
                    entry_url = raw_url
                else:
                    entry_url = 'https://cca.hawaii.gov/ocp/notices/security-breach/'

                entries.append(BreachEntry(
                    company_name=str(row.get('Breached Entity Name', 'Unknown')),
                    date_reported=str(row.get('Date Notified', '')),
                    source='Hawaii DCCA',
                    url=entry_url,
                    state_records_affected=str(row.get('Hawaii Residents Impacted', 'N/A')),
                    location='Hawaii',
                    breach_type='State Registry'
                ))
            
            logger.info(f"Fetched {len(entries)} entries from Hawaii DCCA")
            
        except Exception as e:
            logger.error(f"Failed to fetch Hawaii DCCA: {e}")
        finally:
            if driver:
                driver.quit()
        
        return entries

    # =========================================================================
    # MAIN COLLECTION
    # =========================================================================
    
    def collect_all(self, parallel: bool = True, include_selenium: bool = True) -> List[BreachEntry]:
        """Collect from all sources"""
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
        ]
        
        # Selenium sources (run sequentially to avoid browser conflicts)
        selenium_sources = [
            ('Maine AG', self.fetch_maine_ag),
            ('Texas AG', self.fetch_texas_ag),
            ('Washington AG', self.fetch_washington_ag),
            ('Hawaii DCCA', self.fetch_hawaii_dcca),
        ]
        
        # Fetch basic sources (can be parallel)
        if parallel:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(func): name for name, func in basic_sources}
                for future in as_completed(futures):
                    source_name = futures[future]
                    try:
                        entries = future.result()
                        all_entries.extend(entries)
                        logger.info(f"✓ {source_name}: {len(entries)} entries")
                    except Exception as e:
                        logger.error(f"✗ {source_name} failed: {e}")
        else:
            for name, func in basic_sources:
                try:
                    entries = func()
                    all_entries.extend(entries)
                    logger.info(f"✓ {name}: {len(entries)} entries")
                except Exception as e:
                    logger.error(f"✗ {name} failed: {e}")
        
        # Fetch Selenium sources sequentially
        if include_selenium and self.use_selenium:
            for name, func in selenium_sources:
                try:
                    entries = func()
                    all_entries.extend(entries)
                    logger.info(f"✓ {name}: {len(entries)} entries")
                except Exception as e:
                    logger.error(f"✗ {name} failed: {e}")
        
        # Deduplicate
        seen_ids = set()
        unique_entries = []
        for entry in all_entries:
            if entry.unique_id not in seen_ids:
                seen_ids.add(entry.unique_id)
                unique_entries.append(entry)
        
        logger.info(f"Total unique entries: {len(unique_entries)}")
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
            return datetime.now(timezone.utc)
        
        formats = [
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%m/%d/%y',
            '%B %d, %Y',
            '%b %d, %Y',
            '%Y-%m-%dT%H:%M:%S',
            '%a, %d %b %Y %H:%M:%S %z',
            '%a, %d %b %Y %H:%M:%S %Z',
            '%Y-%m-%d %H:%M:%S',
        ]
        
        for fmt in formats:
            try:
                parsed = datetime.strptime(date_str.strip(), fmt)
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed
            except ValueError:
                continue
        
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
        include_selenium=not args.no_selenium
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
