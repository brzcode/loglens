"""Enrichment service for LogLens - enriches findings with external threat intelligence."""

import asyncio
import ipaddress
import re
import time
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Set, Union, Any, Tuple
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from ..models import Finding


class EnrichmentStatistics(BaseModel):
    """Statistics for enrichment processing."""
    
    ips_queried: int = Field(0, description="Total unique IPs queried for enrichment")
    successful_lookups: int = Field(0, description="Successful API lookups completed")
    api_errors: int = Field(0, description="Number of API errors encountered")
    cache_hits: int = Field(0, description="Number of cache hits (avoiding API calls)")
    providers_used: List[str] = Field(default_factory=list, description="List of providers used")
    total_findings_enriched: int = Field(0, description="Total findings that received enrichment data")
    start_time: Optional[datetime] = Field(None, description="Enrichment start time")
    end_time: Optional[datetime] = Field(None, description="Enrichment end time")
    error_details: List[str] = Field(default_factory=list, description="Detailed error messages")
    
    @property
    def processing_time(self) -> float:
        """Calculate processing time in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.ips_queried == 0:
            return 0.0
        return (self.successful_lookups / self.ips_queried) * 100


class IPReputationData(BaseModel):
    """Container for IP reputation data from a single provider."""
    
    provider: str = Field(..., description="Name of the reputation provider")
    ip_address: str = Field(..., description="IP address that was queried")
    is_malicious: bool = Field(False, description="Whether IP is considered malicious")
    confidence_score: int = Field(0, description="Confidence score (0-100)")
    country_code: Optional[str] = Field(None, description="Country code of the IP")
    organization: Optional[str] = Field(None, description="Organization owning the IP")
    abuse_reports: int = Field(0, description="Number of abuse reports")
    last_seen: Optional[datetime] = Field(None, description="Last time IP was seen in threats")
    reputation_score: Optional[int] = Field(None, description="Provider-specific reputation score")
    threat_types: List[str] = Field(default_factory=list, description="Types of threats associated")
    additional_data: Dict[str, Any] = Field(default_factory=dict, description="Provider-specific additional data")
    query_timestamp: datetime = Field(default_factory=datetime.now, description="When this data was retrieved")


class BaseEnrichmentProvider(ABC):
    """Abstract base class for enrichment providers."""
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout
        self.rate_limit_delay = 0.25  # Default 250ms between requests
        self.last_request_time = 0.0
        self.cache: Dict[str, IPReputationData] = {}
        self.statistics = {
            'requests_made': 0,
            'cache_hits': 0,
            'errors': 0,
            'rate_limited': 0
        }
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the name of this provider."""
        pass
    
    @property
    @abstractmethod
    def requires_api_key(self) -> bool:
        """Return whether this provider requires an API key."""
        pass
    
    @abstractmethod
    async def _fetch_reputation(self, ip_address: str) -> Optional[IPReputationData]:
        """Fetch reputation data for an IP address.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            IPReputationData object or None if failed
        """
        pass
    
    def is_private_ip(self, ip_address: str) -> bool:
        """Check if IP address is private/internal."""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved
        except ValueError:
            return False
    
    def is_configured(self) -> bool:
        """Check if provider is properly configured."""
        if self.requires_api_key:
            return self.api_key is not None and len(self.api_key.strip()) > 0
        return True
    
    async def _respect_rate_limit(self):
        """Ensure rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    async def get_reputation(self, ip_address: str) -> Optional[IPReputationData]:
        """Get reputation data for an IP address with caching and rate limiting.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            IPReputationData object or None if failed/unavailable
        """
        # Skip private IPs
        if self.is_private_ip(ip_address):
            return None
        
        # Check cache first
        if ip_address in self.cache:
            self.statistics['cache_hits'] += 1
            return self.cache[ip_address]
        
        # Check if provider is configured
        if not self.is_configured():
            return None
        
        try:
            # Respect rate limiting
            await self._respect_rate_limit()
            
            # Fetch reputation data
            reputation_data = await self._fetch_reputation(ip_address)
            
            if reputation_data:
                # Cache the result
                self.cache[ip_address] = reputation_data
                self.statistics['requests_made'] += 1
                return reputation_data
            else:
                self.statistics['errors'] += 1
                return None
                
        except Exception as e:
            self.statistics['errors'] += 1
            # Don't cache errors, allow retry later
            return None
    
    def clear_cache(self):
        """Clear the reputation cache."""
        self.cache.clear()
    
    def get_statistics(self) -> Dict[str, int]:
        """Get provider statistics."""
        return self.statistics.copy()


class EnrichmentEngine:
    """Orchestrator for multiple enrichment providers."""
    
    def __init__(self):
        self.providers: List[BaseEnrichmentProvider] = []
        self.statistics = EnrichmentStatistics()
        self.ip_cache: Dict[str, Dict[str, IPReputationData]] = {}  # ip -> {provider -> data}
    
    def add_provider(self, provider: BaseEnrichmentProvider):
        """Add an enrichment provider."""
        if provider.is_configured():
            self.providers.append(provider)
            if provider.provider_name not in self.statistics.providers_used:
                self.statistics.providers_used.append(provider.provider_name)
    
    def _extract_ips_from_findings(self, findings: List[Finding]) -> Set[str]:
        """Extract unique IP addresses from findings for enrichment."""
        ips = set()
        
        for finding in findings:
            # Add the primary IP address from the log entry
            ips.add(str(finding.log_entry.ip_address))
            
            # Extract additional IPs from enrichment data if present
            if finding.enrichment_data:
                # Look for IPs in request lines, user agents, etc.
                text_fields = [
                    finding.log_entry.request_line,
                    finding.log_entry.user_agent or '',
                    finding.log_entry.referer or ''
                ]
                
                for text in text_fields:
                    # Simple IP regex pattern
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    found_ips = re.findall(ip_pattern, text)
                    for ip in found_ips:
                        try:
                            # Validate it's a real IP
                            ipaddress.ip_address(ip)
                            ips.add(ip)
                        except ValueError:
                            continue
        
        return ips
    
    async def _enrich_ip(self, ip_address: str) -> Dict[str, IPReputationData]:
        """Enrich a single IP address using all available providers."""
        enrichment_data = {}
        
        # Check cache first
        if ip_address in self.ip_cache:
            return self.ip_cache[ip_address]
        
        # Query all providers
        for provider in self.providers:
            try:
                reputation_data = await provider.get_reputation(ip_address)
                if reputation_data:
                    enrichment_data[provider.provider_name] = reputation_data
                    self.statistics.successful_lookups += 1
                else:
                    self.statistics.api_errors += 1
            except Exception as e:
                self.statistics.api_errors += 1
                self.statistics.error_details.append(
                    f"Error querying {provider.provider_name} for {ip_address}: {str(e)}"
                )
        
        # Cache the results
        if enrichment_data:
            self.ip_cache[ip_address] = enrichment_data
        
        return enrichment_data
    
    def _build_enrichment_data(self, ip_reputation_data: Dict[str, Dict[str, IPReputationData]]) -> Dict[str, Any]:
        """Build the enrichment data structure for findings."""
        if not ip_reputation_data:
            return {}
        
        enrichment_data = {
            "ip_reputation": {},
            "enrichment_timestamp": datetime.now().isoformat(),
            "providers_queried": list(self.statistics.providers_used),
            "providers_successful": [],
            "providers_failed": []
        }
        
        # Process each IP's reputation data
        for ip_address, provider_data in ip_reputation_data.items():
            enrichment_data["ip_reputation"][ip_address] = {}
            
            for provider_name, reputation in provider_data.items():
                # Build provider-specific data structure
                provider_data_dict = {
                    "confidence_score": reputation.confidence_score,
                    "is_malicious": reputation.is_malicious,
                    "country_code": reputation.country_code,
                    "organization": reputation.organization,
                    "abuse_reports": reputation.abuse_reports,
                    "threat_types": reputation.threat_types,
                    "query_timestamp": reputation.query_timestamp.isoformat()
                }
                
                # Add provider-specific fields
                if reputation.reputation_score is not None:
                    provider_data_dict["reputation_score"] = reputation.reputation_score
                
                if reputation.last_seen:
                    provider_data_dict["last_seen"] = reputation.last_seen.isoformat()
                
                # Add additional data
                provider_data_dict.update(reputation.additional_data)
                
                enrichment_data["ip_reputation"][ip_address][provider_name] = provider_data_dict
                
                # Track successful providers
                if provider_name not in enrichment_data["providers_successful"]:
                    enrichment_data["providers_successful"].append(provider_name)
        
        # Identify failed providers
        enrichment_data["providers_failed"] = [
            provider for provider in enrichment_data["providers_queried"]
            if provider not in enrichment_data["providers_successful"]
        ]
        
        return enrichment_data
    
    async def enrich_findings(self, findings: List[Finding]) -> List[Finding]:
        """Enrich findings with IP reputation data.
        
        Args:
            findings: List of findings to enrich
            
        Returns:
            List of enriched findings (original list is modified in-place)
        """
        if not findings or not self.providers:
            return findings
        
        self.statistics.start_time = datetime.now()
        
        # Extract unique IPs to query
        unique_ips = self._extract_ips_from_findings(findings)
        self.statistics.ips_queried = len(unique_ips)
        
        # Enrich each unique IP
        ip_reputation_data: Dict[str, Dict[str, IPReputationData]] = {}
        
        for ip_address in unique_ips:
            reputation_data = await self._enrich_ip(ip_address)
            if reputation_data:
                ip_reputation_data[ip_address] = reputation_data
        
        # Apply enrichment data to findings
        for finding in findings:
            finding_ip = str(finding.log_entry.ip_address)
            
            if finding_ip in ip_reputation_data:
                # Build enrichment data structure
                enrichment_data = self._build_enrichment_data({finding_ip: ip_reputation_data[finding_ip]})
                
                # Merge with existing enrichment data
                if finding.enrichment_data:
                    finding.enrichment_data.update(enrichment_data)
                else:
                    finding.enrichment_data = enrichment_data
                
                self.statistics.total_findings_enriched += 1
        
        self.statistics.end_time = datetime.now()
        return findings
    
    def get_statistics(self) -> EnrichmentStatistics:
        """Get enrichment statistics."""
        return self.statistics
    
    def reset_statistics(self):
        """Reset enrichment statistics for new analysis."""
        self.statistics = EnrichmentStatistics()
        # Also reset provider statistics
        for provider in self.providers:
            provider.statistics = {
                'requests_made': 0,
                'cache_hits': 0,
                'errors': 0,
                'rate_limited': 0
            }
    
    def clear_cache(self):
        """Clear all caches."""
        self.ip_cache.clear()
        for provider in self.providers:
            provider.clear_cache()


class AbuseIPDBProvider(BaseEnrichmentProvider):
    """AbuseIPDB enrichment provider."""
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.base_url = "https://api.abuseipdb.com/api/v2"
        self.rate_limit_delay = 0.2  # 5 requests per second max
        
        # Load API key from config if not provided
        if not self.api_key:
            from ..core.config import get_enrichment_config
            config = get_enrichment_config()
            self.api_key = config.abuseipdb_api_key
    
    @property
    def provider_name(self) -> str:
        """Return the name of this provider."""
        return "abuseipdb"
    
    @property
    def requires_api_key(self) -> bool:
        """Return whether this provider requires an API key."""
        return True
    
    async def _fetch_reputation(self, ip_address: str) -> Optional[IPReputationData]:
        """Fetch reputation data from AbuseIPDB.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            IPReputationData object or None if failed
        """
        if not self.api_key:
            return None
        
        url = f"{self.base_url}/check"
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "LogLens/1.0"
        }
        
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90,
            "verbose": ""
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if "data" in data:
                        result = data["data"]
                        
                        # Parse threat types from reports
                        threat_types = []
                        if result.get("reports"):
                            categories_seen = set()
                            for report in result["reports"]:
                                if "categories" in report:
                                    categories_seen.update(report["categories"])
                            
                            # Map AbuseIPDB categories to threat types
                            category_mapping = {
                                1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
                                4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
                                7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
                                10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
                                13: "VPN IP", 14: "Port Scan", 15: "Hacking",
                                16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force",
                                19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
                                22: "SSH", 23: "IoT Targeted"
                            }
                            
                            threat_types = [
                                category_mapping.get(cat, f"Category {cat}")
                                for cat in categories_seen
                            ]
                        
                        # Determine if malicious based on abuse confidence
                        abuse_confidence = result.get("abuseConfidencePercentage", 0)
                        is_malicious = abuse_confidence >= 50  # 50% threshold
                        
                        return IPReputationData(
                            provider=self.provider_name,
                            ip_address=ip_address,
                            is_malicious=is_malicious,
                            confidence_score=abuse_confidence,
                            country_code=result.get("countryCode"),
                            organization=result.get("domain"),
                            abuse_reports=result.get("totalReports", 0),
                            last_seen=datetime.fromisoformat(result["lastReportedAt"].replace("Z", "+00:00")) if result.get("lastReportedAt") else None,
                            threat_types=threat_types,
                            additional_data={
                                "is_public": result.get("isPublic", True),
                                "usage_type": result.get("usageType"),
                                "isp": result.get("isp"),
                                "total_reports": result.get("totalReports", 0),
                                "num_distinct_users": result.get("numDistinctUsers", 0),
                                "whitelist": result.get("isWhitelisted", False)
                            }
                        )
                
                elif response.status_code == 429:
                    # Rate limited
                    self.statistics['rate_limited'] += 1
                    return None
                    
                elif response.status_code == 401:
                    # Invalid API key
                    return None
                    
                else:
                    # Other HTTP errors
                    return None
                    
        except httpx.TimeoutException:
            # Timeout error
            return None
        except Exception as e:
            # Other errors
            return None
        
        return None


class VirusTotalProvider(BaseEnrichmentProvider):
    """VirusTotal enrichment provider."""
    
    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        super().__init__(api_key, timeout)
        self.base_url = "https://www.virustotal.com/api/v3"
        self.rate_limit_delay = 15.0  # 4 requests per minute for free tier
        
        # Load API key from config if not provided
        if not self.api_key:
            from ..core.config import get_enrichment_config
            config = get_enrichment_config()
            self.api_key = config.virustotal_api_key
    
    @property
    def provider_name(self) -> str:
        """Return the name of this provider."""
        return "virustotal"
    
    @property
    def requires_api_key(self) -> bool:
        """Return whether this provider requires an API key."""
        return True
    
    async def _fetch_reputation(self, ip_address: str) -> Optional[IPReputationData]:
        """Fetch reputation data from VirusTotal.
        
        Args:
            ip_address: IP address to query
            
        Returns:
            IPReputationData object or None if failed
        """
        if not self.api_key:
            return None
        
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        headers = {
            "x-apikey": self.api_key,
            "User-Agent": "LogLens/1.0"
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if "data" in data and "attributes" in data["data"]:
                        attributes = data["data"]["attributes"]
                        
                        # Parse analysis stats
                        stats = attributes.get("last_analysis_stats", {})
                        malicious_count = stats.get("malicious", 0)
                        suspicious_count = stats.get("suspicious", 0)
                        clean_count = stats.get("harmless", 0)
                        undetected_count = stats.get("undetected", 0)
                        
                        total_scans = malicious_count + suspicious_count + clean_count + undetected_count
                        
                        # Calculate confidence score based on detection ratio
                        confidence_score = 0
                        if total_scans > 0:
                            threat_ratio = (malicious_count + suspicious_count) / total_scans
                            confidence_score = int(threat_ratio * 100)
                        
                        # Determine if malicious
                        is_malicious = malicious_count > 0 or confidence_score >= 25
                        
                        # Extract threat types from detected engines
                        threat_types = []
                        if "last_analysis_results" in attributes:
                            for engine, result in attributes["last_analysis_results"].items():
                                if result.get("category") in ["malicious", "suspicious"]:
                                    threat_type = result.get("result", "").lower()
                                    if threat_type and threat_type not in threat_types:
                                        threat_types.append(threat_type.title())
                        
                        # Get last analysis date
                        last_analysis_date = None
                        if "last_analysis_date" in attributes:
                            last_analysis_date = datetime.fromtimestamp(attributes["last_analysis_date"])
                        
                        return IPReputationData(
                            provider=self.provider_name,
                            ip_address=ip_address,
                            is_malicious=is_malicious,
                            confidence_score=confidence_score,
                            country_code=attributes.get("country"),
                            organization=attributes.get("as_owner"),
                            reputation_score=attributes.get("reputation"),
                            last_seen=last_analysis_date,
                            threat_types=threat_types,
                            additional_data={
                                "malicious_count": malicious_count,
                                "suspicious_count": suspicious_count,
                                "clean_count": clean_count,
                                "undetected_count": undetected_count,
                                "total_votes": {
                                    "harmless": attributes.get("total_votes", {}).get("harmless", 0),
                                    "malicious": attributes.get("total_votes", {}).get("malicious", 0)
                                },
                                "as_number": attributes.get("asn"),
                                "as_owner": attributes.get("as_owner"),
                                "network": attributes.get("network")
                            }
                        )
                
                elif response.status_code == 429:
                    # Rate limited
                    self.statistics['rate_limited'] += 1
                    return None
                    
                elif response.status_code == 401:
                    # Invalid API key
                    return None
                    
                elif response.status_code == 404:
                    # IP not found - this is normal, return empty data
                    return IPReputationData(
                        provider=self.provider_name,
                        ip_address=ip_address,
                        is_malicious=False,
                        confidence_score=0,
                        additional_data={"status": "not_found"}
                    )
                    
                else:
                    # Other HTTP errors
                    return None
                    
        except httpx.TimeoutException:
            # Timeout error
            return None
        except Exception as e:
            # Other errors
            return None
        
        return None


def create_enrichment_engine() -> EnrichmentEngine:
    """Factory function to create a configured enrichment engine."""
    from ..core.config import get_enrichment_config
    
    config = get_enrichment_config()
    engine = EnrichmentEngine()
    
    # Add providers based on configuration
    if "abuseipdb" in config.enabled_providers:
        abuseipdb_provider = AbuseIPDBProvider(
            api_key=config.abuseipdb_api_key,
            timeout=config.request_timeout
        )
        abuseipdb_provider.rate_limit_delay = config.rate_limit_delay
        engine.add_provider(abuseipdb_provider)
    
    if "virustotal" in config.enabled_providers:
        virustotal_provider = VirusTotalProvider(
            api_key=config.virustotal_api_key,
            timeout=config.request_timeout
        )
        # VirusTotal has stricter rate limits
        virustotal_provider.rate_limit_delay = max(15.0, config.rate_limit_delay)
        engine.add_provider(virustotal_provider)
    
    return engine 