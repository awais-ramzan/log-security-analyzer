"""
Configuration module.
Loads and manages configuration settings from config.json.
"""

import json
import os


class Config:
    """Configuration class for the analyzer."""
    
    DEFAULT_CONFIG = {
        "detection": {
            "brute_force_threshold": 3,
            "time_window_threshold": 5,
            "time_window_minutes": 5
        },
        "failed_login_keywords": [
            "failed password",
            "invalid user",
            "authentication failure",
            "401",
            "403",
            "unauthorized"
        ]
    }
    
    def __init__(self, config_file="config.json"):
        """
        Initialize configuration from file or use defaults.
        
        Args:
            config_file: Path to configuration file
        """
        self.config_file = config_file
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    self.config = json.load(f)
                # Validate configuration
                self._validate_config()
            except (json.JSONDecodeError, IOError) as e:
                print(f"Warning: Could not load config file '{config_file}': {e}")
                print("Using default configuration.")
                self.config = self.DEFAULT_CONFIG.copy()
            except ValueError as e:
                print(f"Warning: Invalid configuration: {e}")
                print("Using default configuration.")
                self.config = self.DEFAULT_CONFIG.copy()
        else:
            self.config = self.DEFAULT_CONFIG.copy()
    
    def get(self, key, default=None):
        """
        Get configuration value by key (supports nested keys with dots).
        
        Args:
            key: Configuration key (e.g., "detection.brute_force_threshold")
            default: Default value if key not found
            
        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value if value is not None else default
    
    def _validate_config(self):
        """
        Validate configuration values.
        Raises ValueError if configuration is invalid.
        """
        # Validate brute_force_threshold
        threshold = self.get("detection.brute_force_threshold")
        if threshold is not None:
            if not isinstance(threshold, int):
                raise ValueError("brute_force_threshold must be an integer")
            if threshold <= 0:
                raise ValueError("brute_force_threshold must be positive")
        
        # Validate time_window_threshold
        time_threshold = self.get("detection.time_window_threshold")
        if time_threshold is not None:
            if not isinstance(time_threshold, int):
                raise ValueError("time_window_threshold must be an integer")
            if time_threshold <= 0:
                raise ValueError("time_window_threshold must be positive")
        
        # Validate time_window_minutes
        window_minutes = self.get("detection.time_window_minutes")
        if window_minutes is not None:
            if not isinstance(window_minutes, (int, float)):
                raise ValueError("time_window_minutes must be a number")
            if window_minutes <= 0:
                raise ValueError("time_window_minutes must be positive")
        
        # Validate failed_login_keywords
        keywords = self.get("failed_login_keywords")
        if keywords is not None:
            if not isinstance(keywords, list):
                raise ValueError("failed_login_keywords must be a list")
            if len(keywords) == 0:
                raise ValueError("failed_login_keywords cannot be empty")
            if not all(isinstance(k, str) for k in keywords):
                raise ValueError("All failed_login_keywords must be strings")
    
    def get_brute_force_threshold(self):
        """Get brute force detection threshold."""
        return self.get("detection.brute_force_threshold", 3)
    
    def get_time_window_threshold(self):
        """Get time-window detection threshold."""
        return self.get("detection.time_window_threshold", 5)
    
    def get_time_window_minutes(self):
        """Get time window duration in minutes."""
        return self.get("detection.time_window_minutes", 5)
    
    def get_failed_login_keywords(self):
        """Get list of failed login keywords."""
        return self.get("failed_login_keywords", [
            "failed password",
            "invalid user",
            "authentication failure",
            "401",
            "403",
            "unauthorized"
        ])

