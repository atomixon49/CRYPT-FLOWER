"""
Certificate Revocation CLI Commands

This module provides command-line interface commands for checking certificate revocation status.
"""

import os
import json
import click
import base64
from typing import Dict, Any

from ...core.cert_revocation import CertificateRevocationChecker
from ...core.key_management import KeyManager

@click.group(name="revocation")
def cert_revocation_group():
    """Commands for checking certificate revocation status."""
    pass

@cert_revocation_group.command(name="check")
@click.option("--cert", required=True, help="Certificate ID or file path")
@click.option("--issuer", help="Issuer certificate ID or file path")
@click.option("--output", help="Output file path for results")
@click.option("--crl/--no-crl", default=True, help="Check CRLs")
@click.option("--ocsp/--no-ocsp", default=True, help="Check OCSP")
@click.option("--force-refresh", is_flag=True, help="Force refresh of cached CRLs")
def check_revocation_command(cert: str, issuer: str, output: str, crl: bool, ocsp: bool, force_refresh: bool):
    """Check the revocation status of a certificate."""
    try:
        # Initialize components
        key_manager = KeyManager()
        revocation_checker = CertificateRevocationChecker()
        
        # Get the certificate data
        cert_data = None
        if os.path.isfile(cert):
            # Read from file
            with open(cert, "rb") as f:
                cert_data = f.read()
        else:
            # Get from key manager
            cert_data = key_manager.get_key(cert)
            if not cert_data:
                raise ValueError(f"Certificate not found: {cert}")
        
        # Get the issuer certificate data if provided
        issuer_data = None
        if issuer:
            if os.path.isfile(issuer):
                # Read from file
                with open(issuer, "rb") as f:
                    issuer_data = f.read()
            else:
                # Get from key manager
                issuer_data = key_manager.get_key(issuer)
                if not issuer_data:
                    raise ValueError(f"Issuer certificate not found: {issuer}")
        
        # Check revocation status
        revocation_result = revocation_checker.check_revocation(
            certificate=cert_data,
            issuer_certificate=issuer_data,
            check_crl=crl,
            check_ocsp=ocsp,
            force_refresh=force_refresh
        )
        
        # Display results
        click.echo(f"Certificate: {cert}")
        if issuer:
            click.echo(f"Issuer: {issuer}")
        
        click.echo(f"Revocation status: {revocation_result['status']}")
        
        if revocation_result['revoked']:
            click.echo(f"Revoked: Yes")
            click.echo(f"Reason: {revocation_result.get('revocation_reason', 'Unknown')}")
            click.echo(f"Revocation time: {revocation_result.get('revocation_time_str', 'Unknown')}")
        else:
            click.echo(f"Revoked: No")
        
        if crl:
            click.echo("\nCRL check results:")
            for result in revocation_result['crl_results']:
                status = result.get('status')
                url = result.get('crl_url', 'Unknown')
                
                if status == 'good':
                    click.echo(f"  {url}: Good")
                    click.echo(f"    Last update: {result.get('crl_last_update_str', 'Unknown')}")
                    click.echo(f"    Next update: {result.get('crl_next_update_str', 'Unknown')}")
                elif status == 'revoked':
                    click.echo(f"  {url}: Revoked")
                    click.echo(f"    Reason: {result.get('reason', 'Unknown')}")
                    click.echo(f"    Revocation time: {result.get('revocation_time_str', 'Unknown')}")
                else:
                    click.echo(f"  {url}: {status.capitalize()}")
                    if 'error' in result:
                        click.echo(f"    Error: {result['error']}")
        
        if ocsp:
            click.echo("\nOCSP check results:")
            for result in revocation_result['ocsp_results']:
                status = result.get('status')
                url = result.get('ocsp_url', 'Unknown')
                
                if status == 'good':
                    click.echo(f"  {url}: Good")
                    click.echo(f"    This update: {result.get('this_update_str', 'Unknown')}")
                    click.echo(f"    Next update: {result.get('next_update_str', 'Unknown')}")
                elif status == 'revoked':
                    click.echo(f"  {url}: Revoked")
                    click.echo(f"    Reason: {result.get('reason', 'Unknown')}")
                    click.echo(f"    Revocation time: {result.get('revocation_time_str', 'Unknown')}")
                else:
                    click.echo(f"  {url}: {status.capitalize()}")
                    if 'error' in result:
                        click.echo(f"    Error: {result['error']}")
        
        # Save results to file if requested
        if output:
            with open(output, "w") as f:
                json.dump(revocation_result, f, indent=2)
            
            click.echo(f"\nResults saved to: {output}")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cert_revocation_group.command(name="cache-info")
def cache_info_command():
    """Get information about the CRL cache."""
    try:
        # Initialize the revocation checker
        revocation_checker = CertificateRevocationChecker()
        
        # Get cache info
        cache_info = revocation_checker.get_cache_info()
        
        # Display results
        click.echo(f"CRL cache directory: {cache_info['cache_dir']}")
        click.echo(f"Cache timeout: {cache_info['cache_timeout']} seconds")
        click.echo(f"Total files: {cache_info['file_count']}")
        click.echo(f"Total size: {cache_info['total_size']} bytes")
        
        if cache_info['cache_entries']:
            click.echo("\nCached CRLs:")
            for entry in cache_info['cache_entries']:
                click.echo(f"  {entry['url']}")
                click.echo(f"    Cached: {entry['cache_time_str']}")
                click.echo(f"    Expires: {entry['expires_str']}")
                click.echo(f"    Size: {entry['size']} bytes")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cert_revocation_group.command(name="clear-cache")
def clear_cache_command():
    """Clear the CRL cache."""
    try:
        # Initialize the revocation checker
        revocation_checker = CertificateRevocationChecker()
        
        # Clear the cache
        revocation_checker.clear_cache()
        
        click.echo("CRL cache cleared successfully.")
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
