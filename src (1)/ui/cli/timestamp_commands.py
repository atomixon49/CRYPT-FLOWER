"""
Timestamp CLI Commands

This module provides command-line interface commands for timestamping documents and signatures.
"""

import os
import json
import click
import base64
from typing import Dict, Any

from ...core.timestamp import TimestampManager

@click.group(name="timestamp")
def timestamp_group():
    """Commands for timestamping documents and signatures."""
    pass

@timestamp_group.command(name="file")
@click.option("--file", required=True, help="File to timestamp")
@click.option("--output", required=True, help="Output timestamp file path")
@click.option("--algorithm", default="sha256", help="Hash algorithm")
@click.option("--tsa-url", help="URL of the Time Stamping Authority (TSA) server")
@click.option("--tsa-username", help="Username for TSA authentication")
@click.option("--tsa-password", help="Password for TSA authentication")
def timestamp_file_command(file: str, output: str, algorithm: str, tsa_url: str, tsa_username: str, tsa_password: str):
    """Create a timestamp for a file."""
    try:
        # Initialize the timestamp manager
        timestamp_manager = TimestampManager(tsa_url, tsa_username, tsa_password)
        
        # Read the file
        with open(file, "rb") as f:
            file_data = f.read()
        
        # Create a timestamp
        use_tsa = tsa_url is not None
        timestamp_result = timestamp_manager.timestamp_data(
            data=file_data,
            hash_algorithm=algorithm,
            use_tsa=use_tsa
        )
        
        # Add file information
        timestamp_result['file_info'] = {
            'filename': os.path.basename(file),
            'file_size': len(file_data)
        }
        
        # Write the timestamp to the output file
        with open(output, "w") as f:
            json.dump(timestamp_result, f, indent=2)
        
        # Display results
        click.echo(f"Timestamp created successfully.")
        click.echo(f"Output saved to: {output}")
        
        if use_tsa:
            timestamp_info = timestamp_result.get('timestamp_info', {})
            click.echo(f"Timestamp: {timestamp_info.get('timestamp_str')}")
            click.echo(f"TSA: {timestamp_info.get('tsa')}")
        else:
            click.echo(f"Timestamp: {timestamp_result.get('local_time')}")
            click.echo("Note: This is a local timestamp, not a TSA timestamp.")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@timestamp_group.command(name="signature")
@click.option("--signature", required=True, help="Signature file to timestamp")
@click.option("--output", required=True, help="Output timestamped signature file path")
@click.option("--algorithm", default="sha256", help="Hash algorithm")
@click.option("--tsa-url", help="URL of the Time Stamping Authority (TSA) server")
@click.option("--tsa-username", help="Username for TSA authentication")
@click.option("--tsa-password", help="Password for TSA authentication")
def timestamp_signature_command(signature: str, output: str, algorithm: str, tsa_url: str, tsa_username: str, tsa_password: str):
    """Create a timestamp for a signature."""
    try:
        # Initialize the timestamp manager
        timestamp_manager = TimestampManager(tsa_url, tsa_username, tsa_password)
        
        # Read the signature file
        with open(signature, "r") as f:
            signature_data = json.load(f)
        
        # Create a timestamp for the signature
        use_tsa = tsa_url is not None
        timestamped_signature = timestamp_manager.timestamp_signature(
            signature_data=signature_data,
            hash_algorithm=algorithm,
            use_tsa=use_tsa
        )
        
        # Write the timestamped signature to the output file
        with open(output, "w") as f:
            json.dump(timestamped_signature, f, indent=2)
        
        # Display results
        click.echo(f"Signature timestamped successfully.")
        click.echo(f"Output saved to: {output}")
        
        timestamp_data = timestamped_signature.get('timestamp', {})
        if use_tsa:
            timestamp_info = timestamp_data.get('timestamp_info', {})
            click.echo(f"Timestamp: {timestamp_info.get('timestamp_str')}")
            click.echo(f"TSA: {timestamp_info.get('tsa')}")
        else:
            click.echo(f"Timestamp: {timestamp_data.get('local_time')}")
            click.echo("Note: This is a local timestamp, not a TSA timestamp.")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@timestamp_group.command(name="verify")
@click.option("--file", help="Original file")
@click.option("--timestamp", required=True, help="Timestamp file")
def verify_timestamp_command(file: str, timestamp: str):
    """Verify a timestamp."""
    try:
        # Initialize the timestamp manager
        timestamp_manager = TimestampManager()
        
        # Read the timestamp file
        with open(timestamp, "r") as f:
            timestamp_data = json.load(f)
        
        # Check if it's a file timestamp or a signature timestamp
        timestamp_type = timestamp_data.get('type')
        
        if timestamp_type in ('tsa_timestamp', 'local_timestamp'):
            # It's a file timestamp
            if not file:
                click.echo("Error: Original file is required for verifying a file timestamp", err=True)
                return
            
            # Read the file
            with open(file, "rb") as f:
                file_data = f.read()
            
            # Verify the timestamp
            verification_result = timestamp_manager.verify_timestamp(
                data=file_data,
                timestamp_data=timestamp_data
            )
        elif 'timestamp' in timestamp_data:
            # It's a signature timestamp
            verification_result = timestamp_manager.verify_signature_timestamp(
                signature_data=timestamp_data
            )
        else:
            click.echo("Error: Unknown timestamp format", err=True)
            return
        
        # Display results
        click.echo(f"Timestamp verification result: {'Valid' if verification_result['valid'] else 'Invalid'}")
        
        if 'hash_valid' in verification_result:
            click.echo(f"Hash verification: {'Valid' if verification_result['hash_valid'] else 'Invalid'}")
        
        if 'token_hash_valid' in verification_result:
            click.echo(f"Token hash verification: {'Valid' if verification_result['token_hash_valid'] else 'Invalid'}")
        
        click.echo(f"Timestamp: {verification_result.get('timestamp_str')}")
        
        if 'tsa' in verification_result:
            click.echo(f"TSA: {verification_result['tsa']}")
        
        if verification_result.get('local'):
            click.echo("Note: This is a local timestamp, not a TSA timestamp.")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
