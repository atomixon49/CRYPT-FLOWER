"""
Multi-Recipient Encryption CLI Commands

This module provides command-line interface commands for multi-recipient encryption.
"""

import os
import json
import click
import base64
from typing import List, Dict, Any

from ...core.multi_recipient_encryption import MultiRecipientEncryption
from ...core.key_management import KeyManager

@click.group(name="multi")
def multi_recipient_group():
    """Commands for multi-recipient encryption."""
    pass

@multi_recipient_group.command(name="encrypt")
@click.option("--file", required=True, help="File to encrypt")
@click.option("--recipients", required=True, help="Comma-separated list of recipient public key IDs")
@click.option("--output", required=True, help="Output file path")
@click.option("--algorithm", default="AES-GCM", help="Symmetric encryption algorithm")
def encrypt_command(file: str, recipients: str, output: str, algorithm: str):
    """Encrypt a file for multiple recipients."""
    try:
        # Parse recipient key IDs
        recipient_key_ids = [key_id.strip() for key_id in recipients.split(",")]
        
        # Initialize components
        key_manager = KeyManager()
        multi_encryption = MultiRecipientEncryption(key_manager)
        
        # Read the file
        with open(file, "rb") as f:
            file_data = f.read()
        
        # Prepare metadata
        metadata = {
            "filename": os.path.basename(file),
            "original_size": len(file_data)
        }
        
        # Encrypt the file
        encrypted_data = multi_encryption.encrypt(
            data=file_data,
            recipient_key_ids=recipient_key_ids,
            symmetric_algorithm=algorithm,
            metadata=metadata
        )
        
        # Write the encrypted data to the output file
        with open(output, "w") as f:
            json.dump(encrypted_data, f, indent=2)
        
        click.echo(f"File encrypted successfully for {len(recipient_key_ids)} recipients.")
        click.echo(f"Output saved to: {output}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@multi_recipient_group.command(name="decrypt")
@click.option("--file", required=True, help="Encrypted file to decrypt")
@click.option("--key", required=True, help="Your private key ID")
@click.option("--output", required=True, help="Output file path")
def decrypt_command(file: str, key: str, output: str):
    """Decrypt a file as one of the recipients."""
    try:
        # Initialize components
        key_manager = KeyManager()
        multi_encryption = MultiRecipientEncryption(key_manager)
        
        # Read the encrypted file
        with open(file, "r") as f:
            encrypted_data = json.load(f)
        
        # Decrypt the file
        decrypted_data = multi_encryption.decrypt(
            encrypted_data=encrypted_data,
            recipient_key_id=key
        )
        
        # Write the decrypted data to the output file
        with open(output, "wb") as f:
            f.write(decrypted_data)
        
        # Get original filename from metadata if available
        original_filename = encrypted_data.get("metadata", {}).get("filename", "unknown")
        
        click.echo(f"File decrypted successfully.")
        click.echo(f"Original filename: {original_filename}")
        click.echo(f"Output saved to: {output}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@multi_recipient_group.command(name="add-recipient")
@click.option("--file", required=True, help="Encrypted file")
@click.option("--new-recipient", required=True, help="New recipient's public key ID")
@click.option("--admin-key", required=True, help="Your private key ID (must be an existing recipient)")
@click.option("--output", help="Output file path (defaults to overwriting the input file)")
def add_recipient_command(file: str, new_recipient: str, admin_key: str, output: str):
    """Add a new recipient to an encrypted file."""
    try:
        # Initialize components
        key_manager = KeyManager()
        multi_encryption = MultiRecipientEncryption(key_manager)
        
        # Read the encrypted file
        with open(file, "r") as f:
            encrypted_data = json.load(f)
        
        # Add the new recipient
        updated_data = multi_encryption.add_recipient(
            encrypted_data=encrypted_data,
            new_recipient_key_id=new_recipient,
            admin_key_id=admin_key
        )
        
        # Determine output path
        output_path = output if output else file
        
        # Write the updated data to the output file
        with open(output_path, "w") as f:
            json.dump(updated_data, f, indent=2)
        
        click.echo(f"Recipient {new_recipient} added successfully.")
        click.echo(f"Output saved to: {output_path}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@multi_recipient_group.command(name="remove-recipient")
@click.option("--file", required=True, help="Encrypted file")
@click.option("--remove-recipient", required=True, help="Recipient to remove (public key ID)")
@click.option("--admin-key", required=True, help="Your private key ID (must be an existing recipient)")
@click.option("--output", help="Output file path (defaults to overwriting the input file)")
def remove_recipient_command(file: str, remove_recipient: str, admin_key: str, output: str):
    """Remove a recipient from an encrypted file."""
    try:
        # Initialize components
        key_manager = KeyManager()
        multi_encryption = MultiRecipientEncryption(key_manager)
        
        # Read the encrypted file
        with open(file, "r") as f:
            encrypted_data = json.load(f)
        
        # Remove the recipient
        updated_data = multi_encryption.remove_recipient(
            encrypted_data=encrypted_data,
            recipient_key_id_to_remove=remove_recipient,
            admin_key_id=admin_key
        )
        
        # Determine output path
        output_path = output if output else file
        
        # Write the updated data to the output file
        with open(output_path, "w") as f:
            json.dump(updated_data, f, indent=2)
        
        click.echo(f"Recipient {remove_recipient} removed successfully.")
        click.echo(f"Output saved to: {output_path}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@multi_recipient_group.command(name="list-recipients")
@click.option("--file", required=True, help="Encrypted file")
def list_recipients_command(file: str):
    """List all recipients of an encrypted file."""
    try:
        # Read the encrypted file
        with open(file, "r") as f:
            encrypted_data = json.load(f)
        
        # Check if it's a multi-recipient encrypted file
        if encrypted_data.get("type") != "multi_recipient_encrypted":
            click.echo("Error: Not a multi-recipient encrypted file", err=True)
            return
        
        # Get the recipients
        recipients = encrypted_data.get("recipients", {})
        
        # Display the recipients
        click.echo(f"File: {file}")
        click.echo(f"Number of recipients: {len(recipients)}")
        click.echo("Recipients:")
        
        # Initialize key manager to get key info
        key_manager = KeyManager()
        
        for key_id in recipients:
            # Try to get key info
            try:
                key_info = key_manager.get_key_info(key_id)
                key_name = key_info.get("label", key_id)
                click.echo(f"  - {key_id} ({key_name})")
            except:
                click.echo(f"  - {key_id}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
