"""
Tests for the key rotation module.
"""

import unittest
import os
import tempfile
import shutil
import json
import time
from pathlib import Path

from src.core.key_management import KeyManager
from src.core.key_rotation import KeyRotationPolicy, KeyRotationManager


class TestKeyRotation(unittest.TestCase):
    """Test cases for the key rotation module."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.key_manager = KeyManager()
        
        # Create a temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create a temporary config file
        self.config_file = os.path.join(self.test_dir, "test_rotation_config.json")
        
        # Initialize the key rotation manager
        self.rotation_manager = KeyRotationManager(
            key_manager=self.key_manager,
            config_file=self.config_file
        )
        
        # Generate a test key
        self.key = self.key_manager.generate_symmetric_key(algorithm='AES', key_size=256)
        self.key_id = list(self.key_manager.active_keys.keys())[-1]
    
    def tearDown(self):
        """Tear down test fixtures."""
        # Stop the rotation manager
        self.rotation_manager.stop()
        
        # Remove the temporary directory and its contents
        shutil.rmtree(self.test_dir)
    
    def test_create_policy(self):
        """Test creating a key rotation policy."""
        # Create a policy
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            rotation_interval_days=30,
            max_bytes_encrypted=1024 * 1024 * 100,  # 100 MB
            max_operations=1000,
            auto_rotate=False
        )
        
        # Verify the policy
        self.assertEqual(policy.key_id, self.key_id)
        self.assertEqual(policy.rotation_interval_days, 30)
        self.assertEqual(policy.max_bytes_encrypted, 1024 * 1024 * 100)
        self.assertEqual(policy.max_operations, 1000)
        self.assertFalse(policy.auto_rotate)
        
        # Verify tracking data
        self.assertEqual(policy.bytes_encrypted, 0)
        self.assertEqual(policy.operation_count, 0)
    
    def test_policy_serialization(self):
        """Test serializing and deserializing a policy."""
        # Create a policy
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            rotation_interval_days=30,
            max_bytes_encrypted=1024 * 1024 * 100,  # 100 MB
            max_operations=1000,
            auto_rotate=False
        )
        
        # Track some usage
        policy.track_usage(bytes_encrypted=1024, operations=5)
        
        # Serialize the policy
        policy_dict = policy.to_dict()
        
        # Deserialize the policy
        restored_policy = KeyRotationPolicy.from_dict(policy_dict)
        
        # Verify the restored policy
        self.assertEqual(restored_policy.key_id, policy.key_id)
        self.assertEqual(restored_policy.rotation_interval_days, policy.rotation_interval_days)
        self.assertEqual(restored_policy.max_bytes_encrypted, policy.max_bytes_encrypted)
        self.assertEqual(restored_policy.max_operations, policy.max_operations)
        self.assertEqual(restored_policy.auto_rotate, policy.auto_rotate)
        self.assertEqual(restored_policy.bytes_encrypted, policy.bytes_encrypted)
        self.assertEqual(restored_policy.operation_count, policy.operation_count)
    
    def test_add_policy(self):
        """Test adding a policy to the rotation manager."""
        # Create a policy
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            rotation_interval_days=30,
            max_bytes_encrypted=1024 * 1024 * 100,  # 100 MB
            max_operations=1000,
            auto_rotate=False
        )
        
        # Add the policy
        self.rotation_manager.add_policy(policy)
        
        # Verify the policy was added
        self.assertIn(self.key_id, self.rotation_manager.policies)
        
        # Verify the policy was saved to the config file
        self.assertTrue(os.path.exists(self.config_file))
        
        # Load the config file and verify the policy
        with open(self.config_file, 'r') as f:
            config_data = json.load(f)
        
        self.assertEqual(len(config_data["policies"]), 1)
        self.assertEqual(config_data["policies"][0]["key_id"], self.key_id)
    
    def test_remove_policy(self):
        """Test removing a policy from the rotation manager."""
        # Create and add a policy
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            rotation_interval_days=30,
            max_bytes_encrypted=1024 * 1024 * 100,  # 100 MB
            max_operations=1000,
            auto_rotate=False
        )
        
        self.rotation_manager.add_policy(policy)
        
        # Verify the policy was added
        self.assertIn(self.key_id, self.rotation_manager.policies)
        
        # Remove the policy
        self.rotation_manager.remove_policy(self.key_id)
        
        # Verify the policy was removed
        self.assertNotIn(self.key_id, self.rotation_manager.policies)
        
        # Verify the policy was removed from the config file
        with open(self.config_file, 'r') as f:
            config_data = json.load(f)
        
        self.assertEqual(len(config_data["policies"]), 0)
    
    def test_track_key_usage(self):
        """Test tracking key usage."""
        # Create and add a policy
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            rotation_interval_days=30,
            max_bytes_encrypted=1024 * 1024 * 100,  # 100 MB
            max_operations=1000,
            auto_rotate=False
        )
        
        self.rotation_manager.add_policy(policy)
        
        # Track some usage
        self.rotation_manager.track_key_usage(
            key_id=self.key_id,
            bytes_encrypted=1024,
            operations=5
        )
        
        # Verify the usage was tracked
        updated_policy = self.rotation_manager.get_policy(self.key_id)
        self.assertEqual(updated_policy.bytes_encrypted, 1024)
        self.assertEqual(updated_policy.operation_count, 5)
    
    def test_should_rotate_time_based(self):
        """Test time-based rotation decision."""
        # Create a policy with a very short rotation interval
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            rotation_interval_days=0.0001,  # About 8.6 seconds
            auto_rotate=False
        )
        
        # Initially, should not rotate
        self.assertFalse(policy.should_rotate())
        
        # Wait for the rotation interval
        time.sleep(10)
        
        # Now, should rotate
        self.assertTrue(policy.should_rotate())
    
    def test_should_rotate_usage_based(self):
        """Test usage-based rotation decision."""
        # Create a policy with usage limits
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            max_bytes_encrypted=1000,
            max_operations=10,
            auto_rotate=False
        )
        
        # Initially, should not rotate
        self.assertFalse(policy.should_rotate())
        
        # Track usage below limits
        policy.track_usage(bytes_encrypted=500, operations=5)
        self.assertFalse(policy.should_rotate())
        
        # Track usage exceeding byte limit
        policy.track_usage(bytes_encrypted=600, operations=1)
        self.assertTrue(policy.should_rotate())
        
        # Create a new policy for operation limit test
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            max_bytes_encrypted=10000,
            max_operations=10,
            auto_rotate=False
        )
        
        # Track usage exceeding operation limit
        policy.track_usage(bytes_encrypted=100, operations=11)
        self.assertTrue(policy.should_rotate())
    
    def test_rotate_symmetric_key(self):
        """Test rotating a symmetric key."""
        # Create a policy
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            rotation_interval_days=30,
            auto_rotate=False
        )
        
        self.rotation_manager.add_policy(policy)
        
        # Rotate the key
        new_key_id = self.rotation_manager.rotate_key(self.key_id)
        
        # Verify the rotation
        self.assertIsNotNone(new_key_id)
        self.assertNotEqual(new_key_id, self.key_id)
        
        # Verify the new key exists
        self.assertIn(new_key_id, self.key_manager.active_keys)
        
        # Verify the old key is archived
        self.assertNotIn(self.key_id, self.key_manager.active_keys)
        
        # Verify the policy was updated
        self.assertNotIn(self.key_id, self.rotation_manager.policies)
        self.assertIn(new_key_id, self.rotation_manager.policies)
    
    def test_rotation_callback(self):
        """Test rotation callback."""
        # Create a policy
        policy = KeyRotationPolicy(
            key_id=self.key_id,
            rotation_interval_days=30,
            auto_rotate=False
        )
        
        self.rotation_manager.add_policy(policy)
        
        # Create a callback
        callback_called = False
        callback_old_key = None
        callback_new_key = None
        
        def rotation_callback(old_key_id, new_key_id):
            nonlocal callback_called, callback_old_key, callback_new_key
            callback_called = True
            callback_old_key = old_key_id
            callback_new_key = new_key_id
        
        # Add the callback
        self.rotation_manager.add_rotation_callback(rotation_callback)
        
        # Rotate the key
        new_key_id = self.rotation_manager.rotate_key(self.key_id)
        
        # Verify the callback was called
        self.assertTrue(callback_called)
        self.assertEqual(callback_old_key, self.key_id)
        self.assertEqual(callback_new_key, new_key_id)


if __name__ == "__main__":
    unittest.main()
