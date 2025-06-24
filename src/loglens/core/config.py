"""Configuration management for LogLens."""

import os
from pathlib import Path
from typing import Optional, Dict, Any
import yaml
from pydantic import BaseModel, Field


class EnrichmentConfig(BaseModel):
    """Configuration for enrichment services."""
    
    # API Keys
    abuseipdb_api_key: Optional[str] = Field(None, description="AbuseIPDB API key")
    virustotal_api_key: Optional[str] = Field(None, description="VirusTotal API key")
    
    # Provider settings
    enabled_providers: list[str] = Field(
        default_factory=lambda: ["abuseipdb", "virustotal"],
        description="List of enabled enrichment providers"
    )
    
    # Rate limiting and timeouts
    request_timeout: int = Field(10, description="HTTP request timeout in seconds")
    rate_limit_delay: float = Field(0.25, description="Delay between requests in seconds")
    max_retries: int = Field(3, description="Maximum retry attempts for failed requests")
    retry_backoff_factor: float = Field(2.0, description="Backoff factor for retries")
    
    # Caching
    cache_enabled: bool = Field(True, description="Whether to cache reputation data")
    cache_ttl_hours: int = Field(24, description="Cache TTL in hours")
    
    # Performance
    concurrent_requests: int = Field(5, description="Maximum concurrent API requests")
    batch_size: int = Field(100, description="Batch size for processing IPs")


class FrequencyDetectionConfig(BaseModel):
    """Configuration for frequency detection features."""
    
    # Core detector settings
    enable_advanced_frequency: bool = Field(True, description="Enable advanced time-windowed frequency detection")
    enable_scanning_detection: bool = Field(True, description="Enable scanning pattern detection")
    enable_behavioral_analysis: bool = Field(True, description="Enable behavioral anomaly detection")
    enable_geographic_analysis: bool = Field(True, description="Enable geographic frequency analysis")
    
    # Time window thresholds
    time_window_failed_logins: Dict[str, int] = Field(
        default_factory=lambda: {
            '1min': 5, '5min': 10, '15min': 20, '1hour': 50
        },
        description="Failed login thresholds per time window"
    )
    time_window_requests: Dict[str, int] = Field(
        default_factory=lambda: {
            '1min': 100, '5min': 250, '15min': 500, '1hour': 1000
        },
        description="Request thresholds per time window"
    )
    
    # Scanning detection settings
    unique_paths_threshold: int = Field(10, description="Threshold for unique paths to trigger scanning detection")
    scan_time_window: int = Field(300, description="Time window for scanning detection in seconds")
    
    # Behavioral analysis settings
    dos_burst_threshold: int = Field(100, description="Request threshold for DoS burst detection")
    user_agent_rotation_threshold: int = Field(5, description="Threshold for user agent rotation detection")
    
    # Geographic analysis settings
    geo_change_threshold: int = Field(3, description="Countries threshold for geographic anomaly detection")
    session_time_window: int = Field(3600, description="Session time window for geographic analysis in seconds")
    high_risk_countries: Dict[str, float] = Field(
        default_factory=lambda: {
            'CN': 1.3, 'RU': 1.4, 'KP': 1.5, 'IR': 1.4, 
            'PK': 1.2, 'BD': 1.2, 'VN': 1.2, 'IN': 1.1
        },
        description="High-risk countries and their risk multipliers"
    )


class LogLensConfig(BaseModel):
    """Main LogLens configuration."""
    
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    frequency_detection: FrequencyDetectionConfig = Field(default_factory=FrequencyDetectionConfig)
    
    # Other configuration sections can be added here
    # parsing: ParsingConfig = Field(default_factory=ParsingConfig)


class ConfigManager:
    """Manages LogLens configuration from multiple sources."""
    
    def __init__(self):
        self.config_paths = [
            Path.home() / ".loglens" / "config.yml",
            Path.home() / ".loglens" / "config.yaml",
            Path.cwd() / "loglens.yml",
            Path.cwd() / "loglens.yaml",
        ]
        self._config: Optional[LogLensConfig] = None
    
    def _load_from_file(self) -> Dict[str, Any]:
        """Load configuration from file."""
        for config_path in self.config_paths:
            if config_path.exists():
                try:
                    with open(config_path, 'r', encoding='utf-8') as f:
                        return yaml.safe_load(f) or {}
                except Exception as e:
                    # Log error but continue to try other files
                    continue
        return {}
    
    def _load_from_env(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {
            "enrichment": {}
        }
        
        # Load enrichment API keys from environment
        abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY") or os.getenv("LOGLENS_ABUSEIPDB_API_KEY")
        if abuseipdb_key:
            env_config["enrichment"]["abuseipdb_api_key"] = abuseipdb_key
        
        virustotal_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("LOGLENS_VIRUSTOTAL_API_KEY")
        if virustotal_key:
            env_config["enrichment"]["virustotal_api_key"] = virustotal_key
        
        # Load other enrichment settings from environment
        env_mappings = {
            "LOGLENS_REQUEST_TIMEOUT": ("enrichment", "request_timeout", int),
            "LOGLENS_RATE_LIMIT_DELAY": ("enrichment", "rate_limit_delay", float),
            "LOGLENS_MAX_RETRIES": ("enrichment", "max_retries", int),
            "LOGLENS_CACHE_ENABLED": ("enrichment", "cache_enabled", lambda x: x.lower() in ['true', '1', 'yes']),
            "LOGLENS_CACHE_TTL_HOURS": ("enrichment", "cache_ttl_hours", int),
            "LOGLENS_CONCURRENT_REQUESTS": ("enrichment", "concurrent_requests", int),
        }
        
        for env_var, (section, key, type_converter) in env_mappings.items():
            value = os.getenv(env_var)
            if value:
                try:
                    env_config[section][key] = type_converter(value)
                except (ValueError, TypeError):
                    # Skip invalid values
                    continue
        
        # Handle enabled providers from environment
        enabled_providers = os.getenv("LOGLENS_ENABLED_PROVIDERS")
        if enabled_providers:
            env_config["enrichment"]["enabled_providers"] = [
                provider.strip() for provider in enabled_providers.split(",")
            ]
        
        return env_config
    
    def _merge_configs(self, file_config: Dict[str, Any], env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge file and environment configurations with env taking precedence."""
        merged = file_config.copy()
        
        for section, values in env_config.items():
            if section not in merged:
                merged[section] = {}
            
            if isinstance(values, dict):
                merged[section].update(values)
            else:
                merged[section] = values
        
        return merged
    
    def load_config(self) -> LogLensConfig:
        """Load configuration from all sources."""
        if self._config is not None:
            return self._config
        
        # Load from file and environment
        file_config = self._load_from_file()
        env_config = self._load_from_env()
        
        # Merge configurations
        merged_config = self._merge_configs(file_config, env_config)
        
        # Create and validate configuration
        self._config = LogLensConfig(**merged_config)
        
        return self._config
    
    def get_enrichment_config(self) -> EnrichmentConfig:
        """Get enrichment configuration."""
        return self.load_config().enrichment
    
    def get_frequency_detection_config(self) -> FrequencyDetectionConfig:
        """Get frequency detection configuration."""
        return self.load_config().frequency_detection
    
    def save_config(self, config_path: Optional[Path] = None) -> None:
        """Save current configuration to file."""
        if self._config is None:
            return
        
        # Use first config path if none specified
        if config_path is None:
            config_path = self.config_paths[0]
        
        # Ensure directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert to dict and save
        config_dict = self._config.model_dump(exclude_unset=True)
        
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump(config_dict, f, default_flow_style=False, indent=2)
    
    def create_sample_config(self, config_path: Optional[Path] = None) -> None:
        """Create a sample configuration file."""
        if config_path is None:
            config_path = self.config_paths[0]
        
        # Ensure directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        sample_config = {
            "enrichment": {
                "abuseipdb_api_key": "your-abuseipdb-api-key-here",
                "virustotal_api_key": "your-virustotal-api-key-here",
                "enabled_providers": ["abuseipdb", "virustotal"],
                "request_timeout": 10,
                "rate_limit_delay": 0.25,
                "max_retries": 3,
                "cache_enabled": True,
                "cache_ttl_hours": 24,
                "concurrent_requests": 5
            }
        }
        
        with open(config_path, 'w', encoding='utf-8') as f:
            f.write("# LogLens Configuration File\n")
            f.write("# Copy this file to ~/.loglens/config.yml and update with your API keys\n\n")
            yaml.safe_dump(sample_config, f, default_flow_style=False, indent=2)


# Global config manager instance
config_manager = ConfigManager()


def get_enrichment_config() -> EnrichmentConfig:
    """Convenience function to get enrichment configuration."""
    return config_manager.get_enrichment_config()


def get_config() -> LogLensConfig:
    """Convenience function to get full configuration."""
    return config_manager.load_config() 