"""
Co-Signing CLI Commands

This module provides command-line interface commands for co-signing documents.
"""

import os
import json
import click
from typing import List, Dict, Any

from ...core.cosign import CoSignatureManager
from ...core.key_management import KeyManager

@click.group(name="cosign")
def cosign_group():
    """Commands for co-signing documents."""
    pass

@cosign_group.command(name="create")
@click.option("--file", required=True, help="File to sign")
@click.option("--key", required=True, help="Your private key ID")
@click.option("--output", required=True, help="Output signature file path")
@click.option("--algorithm", default="RSA-PSS", help="Signature algorithm")
@click.option("--required-signers", help="Comma-separated list of required signer key IDs")
def create_command(file: str, key: str, output: str, algorithm: str, required_signers: str):
    """Create a new co-signature chain."""
    try:
        # Parse required signers if provided
        required_signers_list = None
        if required_signers:
            required_signers_list = [signer.strip() for signer in required_signers.split(",")]
        
        # Initialize components
        key_manager = KeyManager()
        cosign_manager = CoSignatureManager(key_manager)
        
        # Read the file
        with open(file, "rb") as f:
            file_data = f.read()
        
        # Prepare metadata
        metadata = {
            "filename": os.path.basename(file),
            "file_size": len(file_data)
        }
        
        # Create the signature chain
        signature_chain = cosign_manager.create_signature_chain(
            data=file_data,
            signer_key_id=key,
            algorithm=algorithm,
            metadata=metadata,
            required_signers=required_signers_list
        )
        
        # Write the signature chain to the output file
        with open(output, "w") as f:
            json.dump(signature_chain, f, indent=2)
        
        click.echo(f"Co-signature chain created successfully.")
        click.echo(f"Output saved to: {output}")
        
        # Display status
        status = cosign_manager.get_signature_status(signature_chain)
        click.echo(f"Status: {status['status']}")
        click.echo(f"Total signatures: {status['total_signatures']}")
        
        if required_signers_list:
            click.echo(f"Required signers: {len(required_signers_list)}")
            click.echo(f"Missing signers: {len(status['missing_signers'])}")
            
            if status['missing_signers']:
                click.echo("Missing signers:")
                for signer in status['missing_signers']:
                    click.echo(f"  - {signer}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cosign_group.command(name="sign")
@click.option("--file", required=True, help="File that was signed")
@click.option("--signature", required=True, help="Signature chain file")
@click.option("--key", required=True, help="Your private key ID")
@click.option("--algorithm", default="RSA-PSS", help="Signature algorithm")
@click.option("--output", help="Output file path (defaults to overwriting the input signature file)")
def sign_command(file: str, signature: str, key: str, algorithm: str, output: str):
    """Add your signature to an existing co-signature chain."""
    try:
        # Initialize components
        key_manager = KeyManager()
        cosign_manager = CoSignatureManager(key_manager)
        
        # Read the file
        with open(file, "rb") as f:
            file_data = f.read()
        
        # Read the signature chain
        with open(signature, "r") as f:
            signature_chain = json.load(f)
        
        # Add the signature
        updated_chain = cosign_manager.add_signature(
            data=file_data,
            signature_chain=signature_chain,
            signer_key_id=key,
            algorithm=algorithm
        )
        
        # Determine output path
        output_path = output if output else signature
        
        # Write the updated signature chain to the output file
        with open(output_path, "w") as f:
            json.dump(updated_chain, f, indent=2)
        
        click.echo(f"Signature added successfully.")
        click.echo(f"Output saved to: {output_path}")
        
        # Display status
        status = cosign_manager.get_signature_status(updated_chain)
        click.echo(f"Status: {status['status']}")
        click.echo(f"Total signatures: {status['total_signatures']}")
        
        if status['required_signers']:
            click.echo(f"Required signers: {len(status['required_signers']) + len(status['missing_signers'])}")
            click.echo(f"Missing signers: {len(status['missing_signers'])}")
            
            if status['missing_signers']:
                click.echo("Missing signers:")
                for signer in status['missing_signers']:
                    click.echo(f"  - {signer}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cosign_group.command(name="verify")
@click.option("--file", required=True, help="File that was signed")
@click.option("--signature", required=True, help="Signature chain file")
@click.option("--detailed", is_flag=True, help="Show detailed verification results")
def verify_command(file: str, signature: str, detailed: bool):
    """Verify a co-signature chain."""
    try:
        # Initialize components
        key_manager = KeyManager()
        cosign_manager = CoSignatureManager(key_manager)
        
        # Read the file
        with open(file, "rb") as f:
            file_data = f.read()
        
        # Read the signature chain
        with open(signature, "r") as f:
            signature_chain = json.load(f)
        
        # Verify the signature chain
        verification_result = cosign_manager.verify_signature_chain(
            data=file_data,
            signature_chain=signature_chain,
            verify_all=True
        )
        
        # Display results
        click.echo(f"File: {file}")
        click.echo(f"Signature chain: {signature}")
        click.echo(f"Document hash valid: {verification_result['hash_valid']}")
        click.echo(f"All signatures valid: {verification_result['signatures_valid']}")
        click.echo(f"Status: {verification_result['status']}")
        click.echo(f"Complete: {verification_result['complete']}")
        
        if verification_result['missing_signers']:
            click.echo(f"Missing signers: {len(verification_result['missing_signers'])}")
            click.echo("Missing signers:")
            for signer in verification_result['missing_signers']:
                click.echo(f"  - {signer}")
        
        if detailed:
            click.echo("\nDetailed verification results:")
            for result in verification_result['verification_results']:
                signer_id = result['signer_id']
                signer_name = result['signer_info'].get('name', signer_id)
                valid = result['valid']
                sequence = result['sequence']
                
                status_str = "✓ Valid" if valid else "✗ Invalid"
                if 'error' in result:
                    status_str += f" ({result['error']})"
                
                click.echo(f"  {sequence}. {signer_name} ({signer_id}): {status_str}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cosign_group.command(name="status")
@click.option("--signature", required=True, help="Signature chain file")
def status_command(signature: str):
    """Check the status of a co-signature chain."""
    try:
        # Initialize components
        key_manager = KeyManager()
        cosign_manager = CoSignatureManager(key_manager)
        
        # Read the signature chain
        with open(signature, "r") as f:
            signature_chain = json.load(f)
        
        # Get the status
        status = cosign_manager.get_signature_status(signature_chain)
        
        # Display status
        click.echo(f"Signature chain: {signature}")
        click.echo(f"Status: {status['status']}")
        click.echo(f"Total signatures: {status['total_signatures']}")
        
        if status['signatures']:
            click.echo("\nSignatures:")
            for sig in status['signatures']:
                signer_id = sig['signer_id']
                signer_name = sig['signer_info'].get('name', signer_id)
                sequence = sig['sequence']
                timestamp = sig['timestamp']
                
                import datetime
                timestamp_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                
                click.echo(f"  {sequence}. {signer_name} ({signer_id}) - {timestamp_str}")
        
        if status['required_signers']:
            click.echo(f"\nRequired signers: {len(status['required_signers']) + len(status['missing_signers'])}")
            click.echo(f"Missing signers: {len(status['missing_signers'])}")
            
            if status['missing_signers']:
                click.echo("Missing signers:")
                for signer in status['missing_signers']:
                    click.echo(f"  - {signer}")
        
        click.echo(f"\nComplete: {status['complete']}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
