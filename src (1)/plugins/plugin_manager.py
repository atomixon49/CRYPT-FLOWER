"""
Plugin Manager Module

This module provides functionality for loading, managing, and using
document management system plugins.
"""

import os
import sys
import importlib
import logging
import json
from typing import Dict, Any, Optional, List, Union, Type

from .plugin_interface import DocumentManagementPlugin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("plugin_manager")


class PluginManager:
    """
    Manages document management system plugins.
    
    This class is responsible for discovering, loading, and managing
    plugins for document management systems. It provides methods for
    listing available plugins, getting plugin information, and creating
    plugin instances.
    """
    
    def __init__(self, plugins_dir: Optional[str] = None):
        """
        Initialize the plugin manager.
        
        Args:
            plugins_dir: Directory containing plugins. If None, uses the default
                         plugins directory (plugins/implementations).
        """
        if plugins_dir is None:
            # Use default plugins directory
            current_dir = os.path.dirname(os.path.abspath(__file__))
            self.plugins_dir = os.path.join(current_dir, "implementations")
        else:
            self.plugins_dir = plugins_dir
        
        # Create plugins directory if it doesn't exist
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir)
        
        # Dictionary to store plugin classes
        self.plugin_classes: Dict[str, Type[DocumentManagementPlugin]] = {}
        
        # Dictionary to store plugin instances
        self.plugin_instances: Dict[str, DocumentManagementPlugin] = {}
        
        # Dictionary to store plugin configurations
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        
        # Load plugin configurations
        self.config_file = os.path.join(os.path.dirname(self.plugins_dir), "plugin_config.json")
        self._load_plugin_configs()
        
        # Discover plugins
        self._discover_plugins()
    
    def _load_plugin_configs(self) -> None:
        """
        Load plugin configurations from the configuration file.
        """
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    self.plugin_configs = json.load(f)
                logger.info(f"Loaded plugin configurations from {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to load plugin configurations: {str(e)}")
                self.plugin_configs = {}
        else:
            self.plugin_configs = {}
    
    def _save_plugin_configs(self) -> None:
        """
        Save plugin configurations to the configuration file.
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.plugin_configs, f, indent=4)
            logger.info(f"Saved plugin configurations to {self.config_file}")
        except Exception as e:
            logger.error(f"Failed to save plugin configurations: {str(e)}")
    
    def _discover_plugins(self) -> None:
        """
        Discover available plugins in the plugins directory.
        """
        # Add plugins directory to Python path
        if self.plugins_dir not in sys.path:
            sys.path.insert(0, os.path.dirname(self.plugins_dir))
        
        # Get list of plugin modules
        plugin_modules = []
        for item in os.listdir(self.plugins_dir):
            if item.endswith(".py") and not item.startswith("__"):
                plugin_modules.append(item[:-3])  # Remove .py extension
        
        # Import plugin modules and register plugin classes
        for module_name in plugin_modules:
            try:
                # Import the module
                module = importlib.import_module(f"implementations.{module_name}")
                
                # Find plugin classes in the module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    # Check if it's a class that implements DocumentManagementPlugin
                    if (isinstance(attr, type) and
                        issubclass(attr, DocumentManagementPlugin) and
                        attr is not DocumentManagementPlugin):
                        
                        # Create an instance to get plugin info
                        try:
                            plugin_instance = attr()
                            plugin_info = plugin_instance.get_plugin_info()
                            plugin_id = plugin_info.get('id')
                            
                            if plugin_id:
                                # Register the plugin class
                                self.plugin_classes[plugin_id] = attr
                                logger.info(f"Discovered plugin: {plugin_id} ({plugin_info.get('name')})")
                            else:
                                logger.warning(f"Plugin class {attr_name} in {module_name} has no ID")
                        
                        except Exception as e:
                            logger.error(f"Failed to initialize plugin class {attr_name} in {module_name}: {str(e)}")
            
            except Exception as e:
                logger.error(f"Failed to import plugin module {module_name}: {str(e)}")
        
        logger.info(f"Discovered {len(self.plugin_classes)} plugins")
    
    def get_plugin_info(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a plugin.
        
        Args:
            plugin_id: ID of the plugin
        
        Returns:
            Dictionary with plugin information, or None if the plugin is not found
        """
        # Check if we have an instance of this plugin
        if plugin_id in self.plugin_instances:
            return self.plugin_instances[plugin_id].get_plugin_info()
        
        # Check if we have the plugin class
        if plugin_id in self.plugin_classes:
            try:
                # Create a temporary instance to get plugin info
                plugin_instance = self.plugin_classes[plugin_id]()
                return plugin_instance.get_plugin_info()
            except Exception as e:
                logger.error(f"Failed to get plugin info for {plugin_id}: {str(e)}")
                return None
        
        return None
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """
        List all available plugins.
        
        Returns:
            List of dictionaries with plugin information
        """
        plugins = []
        
        for plugin_id in self.plugin_classes:
            plugin_info = self.get_plugin_info(plugin_id)
            if plugin_info:
                # Add configuration status
                plugin_info['configured'] = plugin_id in self.plugin_configs
                plugins.append(plugin_info)
        
        return plugins
    
    def get_plugin(self, plugin_id: str) -> Optional[DocumentManagementPlugin]:
        """
        Get a plugin instance.
        
        Args:
            plugin_id: ID of the plugin
        
        Returns:
            Plugin instance, or None if the plugin is not found
        """
        # Check if we already have an instance
        if plugin_id in self.plugin_instances:
            return self.plugin_instances[plugin_id]
        
        # Check if we have the plugin class
        if plugin_id in self.plugin_classes:
            try:
                # Create a new instance
                plugin_instance = self.plugin_classes[plugin_id]()
                self.plugin_instances[plugin_id] = plugin_instance
                
                # Connect if we have configuration
                if plugin_id in self.plugin_configs:
                    try:
                        plugin_instance.connect(self.plugin_configs[plugin_id])
                    except Exception as e:
                        logger.error(f"Failed to connect to {plugin_id}: {str(e)}")
                
                return plugin_instance
            
            except Exception as e:
                logger.error(f"Failed to create plugin instance for {plugin_id}: {str(e)}")
                return None
        
        return None
    
    def configure_plugin(self, plugin_id: str, config: Dict[str, Any]) -> bool:
        """
        Configure a plugin.
        
        Args:
            plugin_id: ID of the plugin
            config: Plugin configuration
        
        Returns:
            True if configuration was successful, False otherwise
        """
        # Check if the plugin exists
        if plugin_id not in self.plugin_classes:
            logger.error(f"Plugin not found: {plugin_id}")
            return False
        
        # Get or create plugin instance
        plugin = self.get_plugin(plugin_id)
        if not plugin:
            logger.error(f"Failed to create plugin instance for {plugin_id}")
            return False
        
        # Try to connect with the new configuration
        try:
            if plugin.connect(config):
                # Store configuration
                self.plugin_configs[plugin_id] = config
                self._save_plugin_configs()
                return True
            else:
                logger.error(f"Failed to connect to {plugin_id} with provided configuration")
                return False
        
        except Exception as e:
            logger.error(f"Failed to configure plugin {plugin_id}: {str(e)}")
            return False
    
    def unconfigure_plugin(self, plugin_id: str) -> bool:
        """
        Remove configuration for a plugin.
        
        Args:
            plugin_id: ID of the plugin
        
        Returns:
            True if configuration was removed, False otherwise
        """
        # Check if the plugin is configured
        if plugin_id not in self.plugin_configs:
            logger.warning(f"Plugin not configured: {plugin_id}")
            return False
        
        # Remove configuration
        del self.plugin_configs[plugin_id]
        self._save_plugin_configs()
        
        # Disconnect if we have an instance
        if plugin_id in self.plugin_instances:
            try:
                self.plugin_instances[plugin_id].disconnect()
            except Exception as e:
                logger.error(f"Failed to disconnect from {plugin_id}: {str(e)}")
            
            # Remove instance
            del self.plugin_instances[plugin_id]
        
        return True
