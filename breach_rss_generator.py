#!/usr/bin/env python3
"""
Data Breach RSS Feed Generator

Aggregates data breach notifications from:
- State AG registries (Maine, Texas, Washington, Hawaii, California)
- Federal sources (HHS OCR)
- Ransomware trackers (ransomware.live API, redpacketsecurity.com)
- Breach news sites (databreaches.net, breachsense.com)
- HIPAA news (hipaajournal.com)

Outputs a combined RSS feed.
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
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
import feedparser
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class BreachEntry:
    """Normalized breach entry"""
    company_name: str
    date_reported: str
    source: str
    url: str
    description: str = ""
    records_affected: str = "Unknown"
    location: str = ""
    threat_actor: str = ""
    breach_type: str = ""
    
    def to_dict(self) -> Dict:
        return {
            'company_name': self.company_name,
            'date_reported': self.date_reported,
            'source': self.source,
            'url': self.url,
            'description': self.description,
            'records_affected': self.records_affected,
            'location': self.location,
            'threat_actor': self.threat_actor,
            'breach_type': self.breach_type
        }
    
    @property
    def unique_id(self) -> str:
        """Generate unique ID for deduplication"""
        content = f"{self.company_name}{self.date_reported}{self.source}"
        return hashlib.md5(content.encode()).hexdigest()


class BreachDataCollector:
    """Collects breach data from multiple sources"""
    
    def __init__(self, use_selenium: bool = False):
        self.use_selenium = use_selenium
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
    
    def _safe_request(self, url: str, timeout: int = 30) -> Optional[requests.Response]:
        """Make a safe HTTP request with error handling"""
        try:
            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request failed for {url}: {e}")
            return None

    # =========================================================================
    # RANSOMWARE.LIVE API
    # =========================================================================
    def fetch_ransomware_live(self, limit: int = 100) -> List[BreachEntry]:
        """Fetch recent victims from ransomware.live API"""
        entries = []
        url = "https://api.ransomware.live/v2/recentvictims"
        
        logger.info("Fetching from ransomware.live API...")
        response = self._safe_request(url)
        
        if not response:
            return entries
        
        try:
            data = response.json()
            for victim in data[:limit]:
                entries.append(BreachEntry(
                    company_name=victim.get('victim', 'Unknown'),
                    date_reported=victim.get('published', victim.get('discovered', '')),
                    source='Ransomware.live',
                    url=victim.get('url', f"https://www.ransomware.live/search?query={victim.get('victim', '')}"),
                    description=victim.get('description', ''),
                    location=victim.get('country', ''),
                    threat_actor=victim.get('group_name', victim.get('group', '')),
                    breach_type='Ransomware'
                ))
            logger.info(f"Fetched {len(entries)} entries from ransomware.live")
        except json.JSONDecodeError as e:
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
                # Extract date
                date_str = ''
                if hasattr(item, 'published'):
                    date_str = item.published
                elif hasattr(item, 'updated'):
                    date_str = item.updated
                
                # Clean description
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
        url = "https://www.breachsense.com/breaches/"
        
        logger.info("Fetching from breachsense.com...")
        response = self._safe_request(url)
        
        if not response:
            return entries
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find breach cards - they use article or div elements with breach info
            # Based on the page structure, breaches are in card-like divs
            breach_links = soup.find_all('a', href=lambda x: x and '/breaches/' in x and 'data-breach' in x)
            
            # Alternative: find by structure
            if not breach_links:
                # Look for headings that link to breach details
                breach_links = soup.select('h3 a[href*="/breaches/"][href*="-data-breach"]')
            
            for link in breach_links[:limit]:
                href = link.get('href', '')
                title = link.get_text(strip=True)
                
                # Extract company name from title or URL
                company_name = title.replace(' Data Breach', '').replace('data-breach', '').strip()
                
                # Try to get parent card for more info
                parent = link.find_parent(['article', 'div'])
                threat_actor = ''
                date_str = ''
                
                if parent:
                    # Look for threat actor info
                    text_content = parent.get_text()
                    if 'Threat Actor' in text_content:
                        actor_match = re.search(r'Threat Actor\s*[:]*\s*(\w+)', text_content)
                        if actor_match:
                            threat_actor = actor_match.group(1)
                    
                    # Look for date
                    date_match = re.search(r'(Dec|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov)\s+\d{1,2},?\s*\d{4}', text_content)
                    if date_match:
                        date_str = date_match.group()
                
                full_url = f"https://www.breachsense.com{href}" if href.startswith('/') else href
                
                entries.append(BreachEntry(
                    company_name=company_name,
                    date_reported=date_str or datetime.now().strftime('%Y-%m-%d'),
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
        # Try the main RSS feed
        urls_to_try = [
            "https://www.hipaajournal.com/feed/",
            "https://www.hipaajournal.com/category/hipaa-breach-news/feed/"
        ]
        
        logger.info("Fetching from HIPAA Journal RSS...")
        
        for url in urls_to_try:
            try:
                feed = feedparser.parse(url)
                if feed.entries:
                    for item in feed.entries[:limit]:
                        # Filter for breach-related entries
                        title = item.get('title', '').lower()
                        if any(kw in title for kw in ['breach', 'hack', 'ransomware', 'exposed', 'attack', 'hipaa']):
                            date_str = item.get('published', item.get('updated', ''))
                            
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
                continue
        
        logger.info(f"Fetched {len(entries)} entries from HIPAA Journal")
        return entries

    # =========================================================================
    # HHS OCR BREACH PORTAL
    # =========================================================================
    def fetch_hhs_ocr(self, limit: int = 100) -> List[BreachEntry]:
        """Fetch from HHS OCR Breach Portal"""
        entries = []
        url = "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"
        
        logger.info("Fetching from HHS OCR...")
        response = self._safe_request(url)
        
        if not response:
            return entries
        
        try:
            tables = pd.read_html(response.text)
            if len(tables) > 1:
                df = tables[1]
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
    # ADDITIONAL SOURCES
    # =========================================================================
    def fetch_have_i_been_pwned_recent(self) -> List[BreachEntry]:
        """Fetch recent breaches from HIBP (if they have a public feed)"""
        entries = []
        # HIBP API requires auth, but we can try their public page
        url = "https://haveibeenpwned.com/PwnedWebsites"
        
        logger.info("Checking Have I Been Pwned...")
        response = self._safe_request(url)
        
        if not response:
            return entries
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Look for breach entries - they're typically in a specific structure
            breach_items = soup.select('.pwnedWebsite, .breach-item, [class*="breach"]')
            
            for item in breach_items[:30]:
                name_el = item.select_one('.pwnedCompanyTitle, h3, .name')
                date_el = item.select_one('.pwnedCompanyDescription, .date, .added')
                
                if name_el:
                    entries.append(BreachEntry(
                        company_name=name_el.get_text(strip=True),
                        date_reported=date_el.get_text(strip=True) if date_el else '',
                        source='Have I Been Pwned',
                        url=url,
                        breach_type='Data Breach'
                    ))
        except Exception as e:
            logger.warning(f"Failed to parse HIBP: {e}")
        
        return entries

    def fetch_bleeping_computer_rss(self, limit: int = 30) -> List[BreachEntry]:
        """Fetch security news from BleepingComputer"""
        entries = []
        url = "https://www.bleepingcomputer.com/feed/"
        
        logger.info("Fetching from BleepingComputer RSS...")
        
        try:
            feed = feedparser.parse(url)
            for item in feed.entries[:limit]:
                title = item.get('title', '').lower()
                # Filter for breach/ransomware related
                if any(kw in title for kw in ['breach', 'ransomware', 'hack', 'leak', 'attack', 'data']):
                    description = ''
                    if hasattr(item, 'summary'):
                        soup = BeautifulSoup(item.summary, 'html.parser')
                        description = soup.get_text()[:500]
                    
                    entries.append(BreachEntry(
                        company_name=item.get('title', 'Unknown'),
                        date_reported=item.get('published', ''),
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
    # MAIN COLLECTION METHOD
    # =========================================================================
    def collect_all(self, parallel: bool = True) -> List[BreachEntry]:
        """Collect from all sources"""
        all_entries = []
        
        sources = [
            ('ransomware.live', self.fetch_ransomware_live),
            ('databreaches.net', self.fetch_databreaches_net),
            ('breachsense.com', self.fetch_breachsense),
            ('HIPAA Journal', self.fetch_hipaa_journal),
            ('HHS OCR', self.fetch_hhs_ocr),
            ('California AG', self.fetch_california_ag),
            ('BleepingComputer', self.fetch_bleeping_computer_rss),
            ('Red Packet Security', self.fetch_red_packet_security),
        ]
        
        if parallel:
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = {executor.submit(func): name for name, func in sources}
                for future in as_completed(futures):
                    source_name = futures[future]
                    try:
                        entries = future.result()
                        all_entries.extend(entries)
                        logger.info(f"✓ {source_name}: {len(entries)} entries")
                    except Exception as e:
                        logger.error(f"✗ {source_name} failed: {e}")
        else:
            for name, func in sources:
                try:
                    entries = func()
                    all_entries.extend(entries)
                    logger.info(f"✓ {name}: {len(entries)} entries")
                except Exception as e:
                    logger.error(f"✗ {name} failed: {e}")
        
        # Deduplicate by unique ID
        seen_ids = set()
        unique_entries = []
        for entry in all_entries:
            if entry.unique_id not in seen_ids:
                seen_ids.add(entry.unique_id)
                unique_entries.append(entry)
        
        logger.info(f"Total unique entries: {len(unique_entries)}")
        return unique_entries


class RSSFeedGenerator:
    """Generate RSS feed from breach entries"""
    
    def __init__(self, 
                 title: str = "Data Breach & Ransomware Feed",
                 link: str = "https://example.com/breaches",
                 description: str = "Aggregated data breach notifications from multiple sources"):
        self.fg = FeedGenerator()
        self.fg.title(title)
        self.fg.link(href=link, rel='alternate')
        self.fg.description(description)
        self.fg.language('en')
        self.fg.lastBuildDate(datetime.now(timezone.utc))
        
    def add_entries(self, entries: List[BreachEntry]):
        """Add breach entries to the feed"""
        for entry in entries:
            fe = self.fg.add_entry()
            fe.id(entry.unique_id)
            fe.title(entry.company_name)
            fe.link(href=entry.url)
            
            # Build description
            desc_parts = []
            if entry.description:
                desc_parts.append(entry.description)
            if entry.threat_actor:
                desc_parts.append(f"Threat Actor: {entry.threat_actor}")
            if entry.records_affected and entry.records_affected != 'Unknown':
                desc_parts.append(f"Records Affected: {entry.records_affected}")
            if entry.location:
                desc_parts.append(f"Location: {entry.location}")
            desc_parts.append(f"Source: {entry.source}")
            
            fe.description('\n'.join(desc_parts) if desc_parts else f"Breach reported by {entry.source}")
            
            # Parse and set date
            try:
                if entry.date_reported:
                    # Try various date formats
                    date_str = entry.date_reported
                    parsed_date = None
                    
                    formats = [
                        '%Y-%m-%d',
                        '%m/%d/%Y',
                        '%B %d, %Y',
                        '%b %d, %Y',
                        '%a, %d %b %Y %H:%M:%S %z',
                        '%a, %d %b %Y %H:%M:%S %Z',
                    ]
                    
                    for fmt in formats:
                        try:
                            parsed_date = datetime.strptime(date_str.strip(), fmt)
                            break
                        except ValueError:
                            continue
                    
                    if parsed_date:
                        if parsed_date.tzinfo is None:
                            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                        fe.pubDate(parsed_date)
                    else:
                        fe.pubDate(datetime.now(timezone.utc))
            except Exception:
                fe.pubDate(datetime.now(timezone.utc))
            
            # Add categories
            if entry.breach_type:
                fe.category(term=entry.breach_type)
            fe.category(term=entry.source)
    
    def generate_rss(self) -> str:
        """Generate RSS XML string"""
        return self.fg.rss_str(pretty=True).decode('utf-8')
    
    def generate_atom(self) -> str:
        """Generate Atom XML string"""
        return self.fg.atom_str(pretty=True).decode('utf-8')
    
    def save_rss(self, filepath: str):
        """Save RSS feed to file"""
        self.fg.rss_file(filepath)
        logger.info(f"RSS feed saved to {filepath}")
    
    def save_atom(self, filepath: str):
        """Save Atom feed to file"""
        self.fg.atom_file(filepath)
        logger.info(f"Atom feed saved to {filepath}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate RSS feed from data breach sources')
    parser.add_argument('--output', '-o', default='breaches.xml', help='Output RSS file path')
    parser.add_argument('--format', '-f', choices=['rss', 'atom', 'both'], default='rss', help='Feed format')
    parser.add_argument('--json', '-j', help='Also save as JSON file')
    parser.add_argument('--csv', '-c', help='Also save as CSV file')
    parser.add_argument('--no-parallel', action='store_true', help='Disable parallel fetching')
    args = parser.parse_args()
    
    # Collect data
    collector = BreachDataCollector()
    entries = collector.collect_all(parallel=not args.no_parallel)
    
    # Sort by date (newest first)
    def parse_date_for_sort(entry):
        try:
            date_str = entry.date_reported
            if not date_str:
                return datetime.min
            
            formats = ['%Y-%m-%d', '%m/%d/%Y', '%B %d, %Y', '%b %d, %Y']
            for fmt in formats:
                try:
                    return datetime.strptime(date_str.strip()[:10], fmt)
                except:
                    continue
            return datetime.min
        except:
            return datetime.min
    
    entries.sort(key=parse_date_for_sort, reverse=True)
    
    # Generate feed
    feed_gen = RSSFeedGenerator(
        title="Data Breach & Ransomware Aggregator",
        link="https://github.com/example/breach-feed",  # Update with your URL
        description="Real-time aggregation of data breach notifications from state registries, federal sources, and ransomware trackers"
    )
    feed_gen.add_entries(entries)
    
    # Save outputs
    if args.format in ['rss', 'both']:
        feed_gen.save_rss(args.output if args.output.endswith('.xml') else args.output + '.rss.xml')
    
    if args.format in ['atom', 'both']:
        atom_path = args.output.replace('.xml', '.atom.xml') if args.output.endswith('.xml') else args.output + '.atom.xml'
        feed_gen.save_atom(atom_path)
    
    # Save JSON if requested
    if args.json:
        with open(args.json, 'w') as f:
            json.dump([e.to_dict() for e in entries], f, indent=2)
        logger.info(f"JSON saved to {args.json}")
    
    # Save CSV if requested
    if args.csv:
        df = pd.DataFrame([e.to_dict() for e in entries])
        df.to_csv(args.csv, index=False)
        logger.info(f"CSV saved to {args.csv}")
    
    print(f"\n{'='*60}")
    print(f"Generated feed with {len(entries)} entries")
    print(f"{'='*60}")
    
    # Show summary by source
    from collections import Counter
    source_counts = Counter(e.source for e in entries)
    print("\nEntries by source:")
    for source, count in source_counts.most_common():
        print(f"  {source}: {count}")


if __name__ == '__main__':
    main()
