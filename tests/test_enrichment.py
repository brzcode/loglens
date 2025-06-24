"""Tests for the enrichment service."""

import asyncio
import ipaddress
import pytest
from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

import httpx
from pydantic import ValidationError

from src.loglens.models import Finding, ParsedLogEntry
from src.loglens.services.enrichment import (
    EnrichmentStatistics, IPReputationData, BaseEnrichmentProvider,
    EnrichmentEngine, AbuseIPDBProvider, VirusTotalProvider, create_enrichment_engine
)


class TestEnrichmentStatistics:
    """Tests for EnrichmentStatistics model."""
    
    def test_statistics_initialization(self):
        """Test statistics initialization with defaults."""
        stats = EnrichmentStatistics()
        
        assert stats.ips_queried == 0
        assert stats.successful_lookups == 0
        assert stats.api_errors == 0
        assert stats.cache_hits == 0
        assert stats.providers_used == []
        assert stats.total_findings_enriched == 0
        assert stats.start_time is None
        assert stats.end_time is None
        assert stats.error_details == []
    
    def test_processing_time_calculation(self):
        """Test processing time calculation."""
        stats = EnrichmentStatistics()
        
        # No times set
        assert stats.processing_time == 0.0
        
        # Set times
        start_time = datetime(2024, 1, 1, 10, 0, 0)
        end_time = datetime(2024, 1, 1, 10, 0, 5)
        stats.start_time = start_time
        stats.end_time = end_time
        
        assert stats.processing_time == 5.0
    
    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        stats = EnrichmentStatistics()
        
        # No queries
        assert stats.success_rate == 0.0
        
        # With queries
        stats.ips_queried = 10
        stats.successful_lookups = 8
        
        assert stats.success_rate == 80.0


class TestIPReputationData:
    """Tests for IPReputationData model."""
    
    def test_reputation_data_creation(self):
        """Test creating IP reputation data."""
        data = IPReputationData(
            provider="test_provider",
            ip_address="192.168.1.1",
            is_malicious=True,
            confidence_score=75
        )
        
        assert data.provider == "test_provider"
        assert data.ip_address == "192.168.1.1"
        assert data.is_malicious is True
        assert data.confidence_score == 75
        assert data.country_code is None
        assert data.threat_types == []
        assert isinstance(data.query_timestamp, datetime)
    
    def test_reputation_data_with_all_fields(self):
        """Test creating IP reputation data with all fields."""
        last_seen = datetime(2024, 1, 1, 12, 0, 0)
        
        data = IPReputationData(
            provider="abuseipdb",
            ip_address="1.2.3.4",
            is_malicious=True,
            confidence_score=90,
            country_code="CN",
            organization="Evil Corp",
            abuse_reports=25,
            last_seen=last_seen,
            reputation_score=-50,
            threat_types=["malware", "botnet"],
            additional_data={"source": "honeypot"}
        )
        
        assert data.provider == "abuseipdb"
        assert data.country_code == "CN"
        assert data.organization == "Evil Corp"
        assert data.abuse_reports == 25
        assert data.last_seen == last_seen
        assert data.reputation_score == -50
        assert data.threat_types == ["malware", "botnet"]
        assert data.additional_data == {"source": "honeypot"}


class MockEnrichmentProvider(BaseEnrichmentProvider):
    """Mock enrichment provider for testing."""
    
    def __init__(self, api_key=None, timeout=10, provider_name="mock", requires_key=True):
        super().__init__(api_key, timeout)
        self._provider_name = provider_name
        self._requires_key = requires_key
        self.fetch_responses = {}  # IP -> response mapping
    
    @property
    def provider_name(self) -> str:
        return self._provider_name
    
    @property
    def requires_api_key(self) -> bool:
        return self._requires_key
    
    async def _fetch_reputation(self, ip_address: str):
        """Mock fetch that returns predefined responses."""
        if ip_address in self.fetch_responses:
            response = self.fetch_responses[ip_address]
            if response is None:
                return None
            return IPReputationData(
                provider=self.provider_name,
                ip_address=ip_address,
                **response
            )
        return None


class TestBaseEnrichmentProvider:
    """Tests for BaseEnrichmentProvider base class."""
    
    def test_provider_initialization(self):
        """Test provider initialization."""
        provider = MockEnrichmentProvider(api_key="test_key", timeout=15)
        
        assert provider.api_key == "test_key"
        assert provider.timeout == 15
        assert provider.rate_limit_delay == 0.25
        assert provider.cache == {}
        assert provider.statistics['requests_made'] == 0
    
    def test_is_private_ip(self):
        """Test private IP detection."""
        provider = MockEnrichmentProvider()
        
        # Private IPs
        assert provider.is_private_ip("192.168.1.1") is True
        assert provider.is_private_ip("10.0.0.1") is True
        assert provider.is_private_ip("172.16.1.1") is True
        assert provider.is_private_ip("127.0.0.1") is True
        
        # Public IPs
        assert provider.is_private_ip("8.8.8.8") is False
        assert provider.is_private_ip("1.2.3.4") is False
        
        # Invalid IP
        assert provider.is_private_ip("invalid") is False
    
    def test_is_configured(self):
        """Test provider configuration check."""
        # Provider that requires API key
        provider = MockEnrichmentProvider(requires_key=True)
        assert provider.is_configured() is False
        
        provider.api_key = "test_key"
        assert provider.is_configured() is True
        
        provider.api_key = "   "  # Whitespace only
        assert provider.is_configured() is False
        
        # Provider that doesn't require API key
        provider = MockEnrichmentProvider(requires_key=False)
        assert provider.is_configured() is True
    
    @pytest.mark.asyncio
    async def test_get_reputation_private_ip(self):
        """Test reputation lookup skips private IPs."""
        provider = MockEnrichmentProvider(api_key="test_key")
        
        result = await provider.get_reputation("192.168.1.1")
        assert result is None
        assert provider.statistics['requests_made'] == 0
    
    @pytest.mark.asyncio
    async def test_get_reputation_not_configured(self):
        """Test reputation lookup when not configured."""
        provider = MockEnrichmentProvider(requires_key=True)  # No API key
        
        result = await provider.get_reputation("1.2.3.4")
        assert result is None
        assert provider.statistics['requests_made'] == 0
    
    @pytest.mark.asyncio
    async def test_get_reputation_success(self):
        """Test successful reputation lookup."""
        provider = MockEnrichmentProvider(api_key="test_key")
        provider.fetch_responses["1.2.3.4"] = {
            "is_malicious": True,
            "confidence_score": 85
        }
        
        result = await provider.get_reputation("1.2.3.4")
        
        assert result is not None
        assert result.ip_address == "1.2.3.4"
        assert result.is_malicious is True
        assert result.confidence_score == 85
        assert provider.statistics['requests_made'] == 1
        assert "1.2.3.4" in provider.cache
    
    @pytest.mark.asyncio
    async def test_get_reputation_cache_hit(self):
        """Test reputation lookup cache hit."""
        provider = MockEnrichmentProvider(api_key="test_key")
        provider.fetch_responses["1.2.3.4"] = {"is_malicious": False, "confidence_score": 0}
        
        # First call
        result1 = await provider.get_reputation("1.2.3.4")
        assert result1 is not None
        assert provider.statistics['requests_made'] == 1
        assert provider.statistics['cache_hits'] == 0
        
        # Second call (cache hit)
        result2 = await provider.get_reputation("1.2.3.4")
        assert result2 is not None
        assert result2.ip_address == result1.ip_address
        assert provider.statistics['requests_made'] == 1  # No additional request
        assert provider.statistics['cache_hits'] == 1
    
    @pytest.mark.asyncio
    async def test_get_reputation_failure(self):
        """Test reputation lookup failure."""
        provider = MockEnrichmentProvider(api_key="test_key")
        provider.fetch_responses["1.2.3.4"] = None  # Simulate failure
        
        result = await provider.get_reputation("1.2.3.4")
        assert result is None
        assert provider.statistics['errors'] == 1
        assert "1.2.3.4" not in provider.cache  # Failed results not cached
    
    def test_clear_cache(self):
        """Test cache clearing."""
        provider = MockEnrichmentProvider(api_key="test_key")
        provider.cache["1.2.3.4"] = IPReputationData(
            provider="test", ip_address="1.2.3.4"
        )
        
        assert len(provider.cache) == 1
        provider.clear_cache()
        assert len(provider.cache) == 0


class TestEnrichmentEngine:
    """Tests for EnrichmentEngine orchestrator."""
    
    def test_engine_initialization(self):
        """Test engine initialization."""
        engine = EnrichmentEngine()
        
        assert engine.providers == []
        assert isinstance(engine.statistics, EnrichmentStatistics)
        assert engine.ip_cache == {}
    
    def test_add_provider(self):
        """Test adding providers to engine."""
        engine = EnrichmentEngine()
        
        # Configured provider
        provider1 = MockEnrichmentProvider(api_key="test_key")
        engine.add_provider(provider1)
        assert len(engine.providers) == 1
        assert "mock" in engine.statistics.providers_used
        
        # Unconfigured provider (should be skipped)
        provider2 = MockEnrichmentProvider(requires_key=True)  # No API key
        engine.add_provider(provider2)
        assert len(engine.providers) == 1  # Still 1, not added
    
    def test_extract_ips_from_findings(self):
        """Test IP extraction from findings."""
        engine = EnrichmentEngine()
        
        # Create test findings
        findings = [
            Finding(
                log_entry=ParsedLogEntry(
                    ip_address=ipaddress.ip_address("1.2.3.4"),
                    timestamp=datetime.now(),
                    request_line="GET / HTTP/1.1",
                    status_code=200,
                    raw_line="test"
                ),
                finding_type="Test",
                description="Test finding"
            ),
            Finding(
                log_entry=ParsedLogEntry(
                    ip_address=ipaddress.ip_address("5.6.7.8"),
                    timestamp=datetime.now(),
                    request_line="POST /api HTTP/1.1",
                    status_code=200,
                    raw_line="test"
                ),
                finding_type="Test",
                description="Test finding 2"
            )
        ]
        
        ips = engine._extract_ips_from_findings(findings)
        assert ips == {"1.2.3.4", "5.6.7.8"}
    
    def test_extract_ips_duplicate_handling(self):
        """Test IP extraction handles duplicates."""
        engine = EnrichmentEngine()
        
        # Create findings with duplicate IPs
        findings = [
            Finding(
                log_entry=ParsedLogEntry(
                    ip_address=ipaddress.ip_address("1.2.3.4"),
                    timestamp=datetime.now(),
                    request_line="GET / HTTP/1.1",
                    status_code=200,
                    raw_line="test"
                ),
                finding_type="Test",
                description="Test finding 1"
            ),
            Finding(
                log_entry=ParsedLogEntry(
                    ip_address=ipaddress.ip_address("1.2.3.4"),
                    timestamp=datetime.now(),
                    request_line="POST /api HTTP/1.1",
                    status_code=200,
                    raw_line="test"
                ),
                finding_type="Test",
                description="Test finding 2"
            )
        ]
        
        ips = engine._extract_ips_from_findings(findings)
        assert ips == {"1.2.3.4"}
    
    def test_build_enrichment_data(self):
        """Test enrichment data structure building."""
        engine = EnrichmentEngine()
        engine.statistics.providers_used = ["provider1", "provider2"]
        
        ip_reputation_data = {
            "1.2.3.4": {
                "provider1": IPReputationData(
                    provider="provider1",
                    ip_address="1.2.3.4",
                    is_malicious=True,
                    confidence_score=85,
                    country_code="CN"
                )
            }
        }
        
        result = engine._build_enrichment_data(ip_reputation_data)
        
        assert "ip_reputation" in result
        assert "enrichment_timestamp" in result
        assert result["providers_queried"] == ["provider1", "provider2"]
        assert result["providers_successful"] == ["provider1"]
        assert result["providers_failed"] == ["provider2"]
        assert "1.2.3.4" in result["ip_reputation"]
        assert "provider1" in result["ip_reputation"]["1.2.3.4"]
    
    @pytest.mark.asyncio
    async def test_enrich_findings_no_providers(self):
        """Test enrichment with no providers."""
        engine = EnrichmentEngine()
        findings = []
        
        result = await engine.enrich_findings(findings)
        assert result == findings
        assert engine.statistics.ips_queried == 0
    
    @pytest.mark.asyncio
    async def test_enrich_findings_success(self):
        """Test successful findings enrichment."""
        engine = EnrichmentEngine()
        
        # Add mock provider
        provider = MockEnrichmentProvider(api_key="test_key")
        provider.fetch_responses["1.2.3.4"] = {
            "is_malicious": True,
            "confidence_score": 90
        }
        engine.add_provider(provider)
        
        # Create test finding
        finding = Finding(
            log_entry=ParsedLogEntry(
                ip_address=ipaddress.ip_address("1.2.3.4"),
                timestamp=datetime.now(),
                request_line="GET / HTTP/1.1",
                status_code=200,
                raw_line="test"
            ),
            finding_type="Test",
            description="Test finding"
        )
        
        findings = [finding]
        result = await engine.enrich_findings(findings)
        
        assert len(result) == 1
        assert result[0].enrichment_data is not None
        assert "ip_reputation" in result[0].enrichment_data
        assert engine.statistics.ips_queried == 1
        assert engine.statistics.successful_lookups == 1
        assert engine.statistics.total_findings_enriched == 1


class TestAbuseIPDBProvider:
    """Tests for AbuseIPDBProvider."""
    
    def test_provider_properties(self):
        """Test provider properties."""
        provider = AbuseIPDBProvider(api_key="test_key")
        
        assert provider.provider_name == "abuseipdb"
        assert provider.requires_api_key is True
        assert provider.base_url == "https://api.abuseipdb.com/api/v2"
        assert provider.rate_limit_delay == 0.2
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.get')
    async def test_fetch_reputation_success(self, mock_get):
        """Test successful AbuseIPDB API call."""
        provider = AbuseIPDBProvider(api_key="test_key")
        
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "ipAddress": "1.2.3.4",
                "isPublic": True,
                "abuseConfidencePercentage": 75,
                "countryCode": "CN",
                "usageType": "datacenter",
                "domain": "example.com",
                "totalReports": 5,
                "numDistinctUsers": 3,
                "isWhitelisted": False,
                "lastReportedAt": "2024-01-15T10:30:00Z",
                "reports": [
                    {"categories": [1, 4]},
                    {"categories": [2]}
                ]
            }
        }
        mock_get.return_value = mock_response
        
        result = await provider._fetch_reputation("1.2.3.4")
        
        assert result is not None
        assert result.provider == "abuseipdb"
        assert result.ip_address == "1.2.3.4"
        assert result.is_malicious is True  # 75% >= 50%
        assert result.confidence_score == 75
        assert result.country_code == "CN"
        assert result.organization == "example.com"
        assert result.abuse_reports == 5
        assert "DNS Compromise" in result.threat_types
        assert "DDoS Attack" in result.threat_types
        assert result.additional_data["is_public"] is True
        assert result.additional_data["usage_type"] == "datacenter"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.get')
    async def test_fetch_reputation_rate_limited(self, mock_get):
        """Test AbuseIPDB rate limiting response."""
        provider = AbuseIPDBProvider(api_key="test_key")
        
        mock_response = Mock()
        mock_response.status_code = 429
        mock_get.return_value = mock_response
        
        result = await provider._fetch_reputation("1.2.3.4")
        
        assert result is None
        assert provider.statistics['rate_limited'] == 1
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.get')
    async def test_fetch_reputation_invalid_key(self, mock_get):
        """Test AbuseIPDB invalid API key response."""
        provider = AbuseIPDBProvider(api_key="invalid_key")
        
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        result = await provider._fetch_reputation("1.2.3.4")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_fetch_reputation_no_api_key(self):
        """Test AbuseIPDB without API key."""
        provider = AbuseIPDBProvider()  # No API key
        
        result = await provider._fetch_reputation("1.2.3.4")
        
        assert result is None


class TestVirusTotalProvider:
    """Tests for VirusTotalProvider."""
    
    def test_provider_properties(self):
        """Test provider properties."""
        provider = VirusTotalProvider(api_key="test_key")
        
        assert provider.provider_name == "virustotal"
        assert provider.requires_api_key is True
        assert provider.base_url == "https://www.virustotal.com/api/v3"
        assert provider.rate_limit_delay == 15.0
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.get')
    async def test_fetch_reputation_success(self, mock_get):
        """Test successful VirusTotal API call."""
        provider = VirusTotalProvider(api_key="test_key")
        
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "country": "CN",
                    "as_owner": "Evil Corp",
                    "asn": 12345,
                    "network": "1.2.3.0/24",
                    "reputation": -15,
                    "last_analysis_date": 1705312500,
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 60,
                        "undetected": 3
                    },
                    "last_analysis_results": {
                        "Engine1": {"category": "malicious", "result": "Trojan"},
                        "Engine2": {"category": "suspicious", "result": "Suspicious"},
                        "Engine3": {"category": "clean", "result": "Clean"}
                    },
                    "total_votes": {
                        "harmless": 10,
                        "malicious": 5
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        result = await provider._fetch_reputation("1.2.3.4")
        
        assert result is not None
        assert result.provider == "virustotal"
        assert result.ip_address == "1.2.3.4"
        assert result.is_malicious is True  # malicious_count > 0
        assert result.confidence_score == 10  # (5+2)/70 * 100 = 10%
        assert result.country_code == "CN"
        assert result.organization == "Evil Corp"
        assert result.reputation_score == -15
        assert "Trojan" in result.threat_types
        assert "Suspicious" in result.threat_types
        assert result.additional_data["malicious_count"] == 5
        assert result.additional_data["as_number"] == 12345
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.get')
    async def test_fetch_reputation_not_found(self, mock_get):
        """Test VirusTotal IP not found response."""
        provider = VirusTotalProvider(api_key="test_key")
        
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response
        
        result = await provider._fetch_reputation("1.2.3.4")
        
        assert result is not None
        assert result.is_malicious is False
        assert result.confidence_score == 0
        assert result.additional_data["status"] == "not_found"
    
    @pytest.mark.asyncio
    @patch('httpx.AsyncClient.get')
    async def test_fetch_reputation_timeout(self, mock_get):
        """Test VirusTotal timeout handling."""
        provider = VirusTotalProvider(api_key="test_key")
        
        mock_get.side_effect = httpx.TimeoutException("Request timeout")
        
        result = await provider._fetch_reputation("1.2.3.4")
        
        assert result is None


@patch('src.loglens.services.enrichment.get_enrichment_config')
def test_create_enrichment_engine(mock_get_config):
    """Test enrichment engine factory function."""
    # Mock config
    mock_config = Mock()
    mock_config.enabled_providers = ["abuseipdb", "virustotal"]
    mock_config.abuseipdb_api_key = "abuse_key"
    mock_config.virustotal_api_key = "vt_key"
    mock_config.request_timeout = 15
    mock_config.rate_limit_delay = 0.5
    mock_get_config.return_value = mock_config
    
    engine = create_enrichment_engine()
    
    assert len(engine.providers) == 2
    assert any(p.provider_name == "abuseipdb" for p in engine.providers)
    assert any(p.provider_name == "virustotal" for p in engine.providers)
    
    # Check provider configuration
    abuseipdb_provider = next(p for p in engine.providers if p.provider_name == "abuseipdb")
    virustotal_provider = next(p for p in engine.providers if p.provider_name == "virustotal")
    
    assert abuseipdb_provider.api_key == "abuse_key"
    assert abuseipdb_provider.timeout == 15
    assert abuseipdb_provider.rate_limit_delay == 0.5
    
    assert virustotal_provider.api_key == "vt_key"
    assert virustotal_provider.timeout == 15
    assert virustotal_provider.rate_limit_delay == 15.0  # Max of 15.0 and 0.5


@patch('src.loglens.services.enrichment.get_enrichment_config')
def test_create_enrichment_engine_no_providers(mock_get_config):
    """Test enrichment engine with no enabled providers."""
    mock_config = Mock()
    mock_config.enabled_providers = []
    mock_get_config.return_value = mock_config
    
    engine = create_enrichment_engine()
    
    assert len(engine.providers) == 0


if __name__ == "__main__":
    pytest.main([__file__]) 