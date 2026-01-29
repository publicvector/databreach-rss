"""
Blog Generator Module for Data Breach RSS Feed

Generates AI-powered blog posts from breach entries:
1. Extracts article text from breach URLs
2. Validates data sufficiency (gating mechanism)
3. Generates structured blog posts via OpenAI API
4. Caches results to avoid re-generation
"""

import os
import json
import time
import hashlib
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any

import requests
from bs4 import BeautifulSoup

# Optional imports with fallbacks
try:
    from newspaper import Article
    NEWSPAPER_AVAILABLE = True
except ImportError:
    NEWSPAPER_AVAILABLE = False

try:
    from readability import Document
    READABILITY_AVAILABLE = True
except ImportError:
    READABILITY_AVAILABLE = False

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

logger = logging.getLogger(__name__)


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class BlogPost:
    """Generated blog post for a breach entry"""
    id: str  # case_id from BreachEntry
    company_name: str
    title: str
    what_happened: str
    who_is_affected: str
    contact_us: str
    generated_at: str
    source_url: str
    quality_score: float

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ValidationResult:
    """Result of data validation for blog generation"""
    is_valid: bool
    quality_score: float
    reasons: List[str] = field(default_factory=list)


# =============================================================================
# ARTICLE EXTRACTOR
# =============================================================================

class ArticleExtractor:
    """Extract article text from URLs using multiple methods"""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def extract(self, url: str) -> Optional[str]:
        """Extract article text from URL, trying multiple methods"""
        if not url or not url.startswith('http'):
            return None

        # Try newspaper3k first (best for news articles)
        if NEWSPAPER_AVAILABLE:
            text = self._extract_newspaper(url)
            if text and len(text) >= 100:
                logger.debug(f"Extracted {len(text)} chars via newspaper3k from {url}")
                return text

        # Try readability-lxml second
        if READABILITY_AVAILABLE:
            text = self._extract_readability(url)
            if text and len(text) >= 100:
                logger.debug(f"Extracted {len(text)} chars via readability from {url}")
                return text

        # Fallback to BeautifulSoup
        text = self._extract_beautifulsoup(url)
        if text and len(text) >= 100:
            logger.debug(f"Extracted {len(text)} chars via BeautifulSoup from {url}")
            return text

        return None

    def _extract_newspaper(self, url: str) -> Optional[str]:
        """Extract using newspaper3k library"""
        try:
            article = Article(url)
            article.download()
            article.parse()
            return article.text
        except Exception as e:
            logger.debug(f"newspaper3k extraction failed for {url}: {e}")
            return None

    def _extract_readability(self, url: str) -> Optional[str]:
        """Extract using readability-lxml library"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            doc = Document(response.text)
            # Get text from the readable content
            soup = BeautifulSoup(doc.summary(), 'html.parser')
            return soup.get_text(separator=' ', strip=True)
        except Exception as e:
            logger.debug(f"readability extraction failed for {url}: {e}")
            return None

    def _extract_beautifulsoup(self, url: str) -> Optional[str]:
        """Extract using BeautifulSoup (basic fallback)"""
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style', 'nav', 'header', 'footer', 'aside']):
                element.decompose()

            # Try to find main content areas
            main_content = (
                soup.find('article') or
                soup.find('main') or
                soup.find('div', class_='content') or
                soup.find('div', class_='post') or
                soup.find('div', class_='entry-content') or
                soup.body
            )

            if main_content:
                # Get text from paragraphs for cleaner output
                paragraphs = main_content.find_all('p')
                if paragraphs:
                    text = ' '.join(p.get_text(strip=True) for p in paragraphs)
                else:
                    text = main_content.get_text(separator=' ', strip=True)
                return text

            return soup.get_text(separator=' ', strip=True)
        except Exception as e:
            logger.debug(f"BeautifulSoup extraction failed for {url}: {e}")
            return None


# =============================================================================
# DATA VALIDATOR
# =============================================================================

class DataValidator:
    """Validate breach entries for blog generation eligibility"""

    # Minimum thresholds
    MIN_DESCRIPTION_LENGTH = 50
    MIN_QUALITY_SCORE = 0.5

    # Invalid company name patterns
    INVALID_NAMES = {'unknown', 'n/a', 'na', 'none', '', 'tbd'}

    def validate(self, entry: Any, extracted_text: Optional[str] = None) -> ValidationResult:
        """
        Validate entry for blog generation eligibility.

        REQUIRED (must pass both):
        - Company name is present and meaningful (not "Unknown")
        - Description OR extracted article has 50+ chars of content

        Quality Score (0.0-1.0):
        - Valid company name: +0.3
        - Description 50+ chars: +0.2
        - Description 200+ chars: +0.1
        - Records affected specified: +0.15
        - Threat actor identified: +0.1
        - Location specified: +0.05
        - Specific breach type: +0.1
        """
        reasons = []

        # Check company name (REQUIRED)
        company_name = getattr(entry, 'company_name', '')
        has_valid_name = bool(
            company_name and
            company_name.lower().strip() not in self.INVALID_NAMES
        )

        if not has_valid_name:
            reasons.append("Missing or invalid company name")

        # Check content availability (REQUIRED)
        description = getattr(entry, 'description', '') or ''
        combined_content = description
        if extracted_text:
            combined_content = f"{description} {extracted_text}"

        has_sufficient_content = len(combined_content.strip()) >= self.MIN_DESCRIPTION_LENGTH

        if not has_sufficient_content:
            reasons.append(f"Insufficient content (need {self.MIN_DESCRIPTION_LENGTH}+ chars)")

        # Calculate quality score
        quality_score = 0.0

        # Company name: +0.3
        if has_valid_name:
            quality_score += 0.3

        # Description 50+ chars: +0.2
        if len(description) >= 50:
            quality_score += 0.2

        # Description 200+ chars: +0.1
        if len(description) >= 200:
            quality_score += 0.1

        # Records affected specified: +0.15
        records = getattr(entry, 'records_affected', '') or ''
        if records and records.lower() not in ['unknown', 'n/a', 'na', '']:
            quality_score += 0.15

        # Threat actor identified: +0.1
        threat_actor = getattr(entry, 'threat_actor', '') or ''
        if threat_actor and threat_actor.lower() not in ['unknown', 'n/a', '']:
            quality_score += 0.1

        # Location specified: +0.05
        location = getattr(entry, 'location', '') or ''
        if location and location.lower() not in ['unknown', 'n/a', '']:
            quality_score += 0.05

        # Specific breach type: +0.1
        breach_type = getattr(entry, 'breach_type', '') or ''
        generic_types = {'data breach', 'breach', 'unknown', ''}
        if breach_type.lower() not in generic_types:
            quality_score += 0.1

        # Final validation
        is_valid = has_valid_name and has_sufficient_content

        if is_valid and quality_score < self.MIN_QUALITY_SCORE:
            reasons.append(f"Quality score {quality_score:.2f} below threshold {self.MIN_QUALITY_SCORE}")
            is_valid = False

        return ValidationResult(
            is_valid=is_valid,
            quality_score=round(quality_score, 2),
            reasons=reasons
        )


# =============================================================================
# RATE LIMITER
# =============================================================================

class RateLimiter:
    """Simple rate limiter to prevent API overload"""

    def __init__(self, requests_per_minute: int = 20):
        self.requests_per_minute = requests_per_minute
        self.min_interval = 60.0 / requests_per_minute
        self.last_request_time = 0.0
        self.lock = threading.Lock()

    def wait(self):
        """Wait if needed to respect rate limit"""
        with self.lock:
            elapsed = time.time() - self.last_request_time
            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)
            self.last_request_time = time.time()


# =============================================================================
# BLOG CACHE
# =============================================================================

class BlogCache:
    """In-memory + file-based cache for generated blogs"""

    def __init__(self, cache_dir: str = "./blog_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.memory_cache: Dict[str, BlogPost] = {}
        self._load_from_disk()

    def _get_cache_path(self, case_id: str) -> Path:
        """Get file path for a cached blog"""
        return self.cache_dir / f"{case_id}.json"

    def _load_from_disk(self):
        """Load all cached blogs from disk into memory"""
        try:
            for cache_file in self.cache_dir.glob("*.json"):
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                    blog = BlogPost(**data)
                    self.memory_cache[blog.id] = blog
            logger.info(f"Loaded {len(self.memory_cache)} cached blogs from disk")
        except Exception as e:
            logger.warning(f"Error loading blog cache: {e}")

    def get(self, case_id: str) -> Optional[BlogPost]:
        """Get a cached blog by case_id"""
        return self.memory_cache.get(case_id)

    def set(self, blog: BlogPost):
        """Cache a blog (memory + disk)"""
        self.memory_cache[blog.id] = blog

        # Write to disk
        cache_path = self._get_cache_path(blog.id)
        try:
            with open(cache_path, 'w') as f:
                json.dump(blog.to_dict(), f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to write blog cache to disk: {e}")

    def has(self, case_id: str) -> bool:
        """Check if a blog is cached"""
        return case_id in self.memory_cache

    def get_all(self) -> List[BlogPost]:
        """Get all cached blogs"""
        return list(self.memory_cache.values())

    def clear(self):
        """Clear all cached blogs"""
        self.memory_cache.clear()
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()


# =============================================================================
# BLOG GENERATOR
# =============================================================================

class BlogGenerator:
    """Generate blog posts from breach entries using Claude API"""

    DEFAULT_MODEL = "claude-sonnet-4-20250514"

    DEFAULT_CONTACT_BOILERPLATE = """If you believe your information may have been affected by this data breach,
you may be entitled to compensation. Contact our experienced data breach attorneys for a free,
confidential consultation. We can help you understand your rights and options."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        contact_boilerplate: Optional[str] = None,
        cache_dir: str = "./blog_cache"
    ):
        self.api_key = api_key or os.environ.get('ANTHROPIC_API_KEY')
        self.model = model or os.environ.get('BLOG_MODEL', self.DEFAULT_MODEL)
        self.contact_boilerplate = (
            contact_boilerplate or
            os.environ.get('BLOG_CONTACT_BOILERPLATE') or
            self.DEFAULT_CONTACT_BOILERPLATE
        )

        self.extractor = ArticleExtractor()
        self.validator = DataValidator()
        self.cache = BlogCache(cache_dir)
        self.rate_limiter = RateLimiter(requests_per_minute=20)

        self.client = None
        if self.api_key and ANTHROPIC_AVAILABLE:
            self.client = anthropic.Anthropic(api_key=self.api_key)
        elif not ANTHROPIC_AVAILABLE:
            logger.warning("Anthropic library not installed. Blog generation disabled.")
        elif not self.api_key:
            logger.warning("ANTHROPIC_API_KEY not set. Blog generation disabled.")

    def _build_prompt(self, entry: Any, extracted_text: Optional[str]) -> str:
        """Build the prompt for OpenAI API"""
        context_parts = []

        context_parts.append(f"Company Name: {entry.company_name}")

        if entry.date_reported:
            context_parts.append(f"Date Reported: {entry.date_reported}")

        if entry.records_affected and entry.records_affected.lower() not in ['unknown', 'n/a']:
            context_parts.append(f"Records Affected: {entry.records_affected}")

        if entry.location:
            context_parts.append(f"Location: {entry.location}")

        if entry.threat_actor:
            context_parts.append(f"Threat Actor: {entry.threat_actor}")

        if entry.breach_type:
            context_parts.append(f"Breach Type: {entry.breach_type}")

        if entry.description:
            context_parts.append(f"Description: {entry.description}")

        if extracted_text:
            # Truncate extracted text to avoid token limits
            truncated = extracted_text[:3000] if len(extracted_text) > 3000 else extracted_text
            context_parts.append(f"Article Content: {truncated}")

        context = "\n".join(context_parts)

        prompt = f"""You are a legal writer creating informative blog posts about data breaches for a law firm website.
Based on the following data breach information, generate two sections for a blog post.

BREACH INFORMATION:
{context}

Generate ONLY the following two sections (do not include titles/headers, just the content):

1. WHAT_HAPPENED: Write 2-3 paragraphs describing what happened in this data breach. Be factual and informative.
Include details about how the breach occurred if known, when it was discovered, and what type of attack it was.
Do not speculate beyond what is provided.

2. WHO_IS_AFFECTED: Write 1-2 paragraphs about who may be affected by this breach. Include:
- The number of people affected (if known)
- The type of data that may have been exposed (personal information, financial data, health records, etc.)
- Who specifically might be affected (customers, employees, patients, etc.)
- The geographic scope if known

Respond in JSON format:
{{"what_happened": "...", "who_is_affected": "..."}}
"""
        return prompt

    def _generate_title(self, company_name: str) -> str:
        """Generate a blog post title"""
        return f"{company_name} Data Breach: What You Need to Know"

    def generate(self, entry: Any, skip_validation: bool = False) -> Optional[BlogPost]:
        """
        Generate a blog post for a breach entry.

        Args:
            entry: BreachEntry object
            skip_validation: If True, skip the validation step (use cached validation)

        Returns:
            BlogPost if successful, None if validation fails or generation fails
        """
        case_id = entry.case_id

        # Check cache first
        cached = self.cache.get(case_id)
        if cached:
            logger.debug(f"Using cached blog for {entry.company_name}")
            return cached

        # Extract article text
        extracted_text = self.extractor.extract(entry.url)

        # Validate
        if not skip_validation:
            validation = self.validator.validate(entry, extracted_text)
            if not validation.is_valid:
                logger.debug(f"Skipping {entry.company_name}: {', '.join(validation.reasons)}")
                return None
            quality_score = validation.quality_score
        else:
            quality_score = 0.5  # Default score for skipped validation

        # Check if we can generate
        if not self.client:
            logger.warning("OpenAI client not available, cannot generate blog")
            return None

        # Generate blog content
        try:
            self.rate_limiter.wait()

            prompt = self._build_prompt(entry, extracted_text)

            response = self.client.messages.create(
                model=self.model,
                max_tokens=1500,
                system="You are a helpful legal writer. Always respond with valid JSON.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            content = response.content[0].text.strip()

            # Parse JSON response
            # Handle potential markdown code blocks
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            content = content.strip()

            result = json.loads(content)

            blog = BlogPost(
                id=case_id,
                company_name=entry.company_name,
                title=self._generate_title(entry.company_name),
                what_happened=result.get('what_happened', ''),
                who_is_affected=result.get('who_is_affected', ''),
                contact_us=self.contact_boilerplate,
                generated_at=datetime.now(timezone.utc).isoformat(),
                source_url=entry.url,
                quality_score=quality_score
            )

            # Cache the result
            self.cache.set(blog)

            logger.info(f"Generated blog for {entry.company_name}")
            return blog

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OpenAI response for {entry.company_name}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to generate blog for {entry.company_name}: {e}")
            return None

    def generate_batch(
        self,
        entries: List[Any],
        limit: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate blogs for a batch of entries.

        Args:
            entries: List of BreachEntry objects
            limit: Maximum number of blogs to generate (None = no limit)

        Returns:
            Dict with 'blogs', 'meta' (total, generated_count, skipped_count)
        """
        blogs = []
        generated_count = 0
        skipped_count = 0

        # First, collect cached blogs
        for entry in entries:
            cached = self.cache.get(entry.case_id)
            if cached:
                blogs.append(cached)

        # Then generate new ones up to limit
        entries_to_generate = [
            e for e in entries
            if not self.cache.has(e.case_id)
        ]

        if limit:
            remaining = limit - len(blogs)
            entries_to_generate = entries_to_generate[:max(0, remaining * 2)]  # Try 2x to account for skips

        for entry in entries_to_generate:
            if limit and len(blogs) >= limit:
                break

            blog = self.generate(entry)
            if blog:
                blogs.append(blog)
                generated_count += 1
            else:
                skipped_count += 1

        return {
            'blogs': [b.to_dict() for b in blogs],
            'meta': {
                'total': len(entries),
                'generated_count': generated_count,
                'skipped_count': skipped_count,
                'cached_count': len(blogs) - generated_count
            }
        }

    def validate_entry(self, entry: Any) -> ValidationResult:
        """Validate an entry without generating"""
        extracted_text = self.extractor.extract(entry.url)
        return self.validator.validate(entry, extracted_text)
