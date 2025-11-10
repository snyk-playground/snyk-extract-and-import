"""
Snyk Organization Extraction Script

This script extracts organization data from a source Snyk group and prepares
it for migration to a target group. It creates a JSON file containing both
the organizations to create and source organization references.

Required environment variables:
    SNYK_TOKEN: API token for the source Snyk tenant
    SOURCE_GROUP_ID: ID of the source Snyk group to extract organizations from
    TARGET_GROUP_ID: ID of the target Snyk group where organizations will be created
    TEMPLATE_ORG_ID: ID of the template organization in target group to copy settings from
    SNYK_LOG_PATH: Directory path where output files will be written

Usage:
    export SNYK_TOKEN="your-snyk-api-token"
    export SOURCE_GROUP_ID="your-source-group-id"
    export TARGET_GROUP_ID="your-target-group-id"
    export TEMPLATE_ORG_ID="your-template-org-id"
    export SNYK_LOG_PATH="/path/to/snyk-logs"
    python3 org_extraction.py
    
Output:
    Creates snyk-orgs-to-create.json with organization migration data.
"""

import json
import os
import sys
from typing import List, Dict, Any

import requests


# Configuration from environment variables
TARGET_GROUP_ID = os.getenv("TARGET_GROUP_ID")
SOURCE_GROUP_ID = os.getenv("SOURCE_GROUP_ID")
TEMPLATE_ORG_ID = os.getenv("TEMPLATE_ORG_ID")  # This is the organization in target group to copy settings from
SNYK_LOG_PATH = os.getenv("SNYK_LOG_PATH", ".")  # Default to current directory if not set
API_VERSION = "2024-06-18"

# File paths (will be combined with SNYK_LOG_PATH)
OUTPUT_FILE = "snyk-orgs-to-create.json"
SOURCE_ORGS_FILE = "snyk-source-orgs.json"


def get_api_headers(api_token: str) -> Dict[str, str]:
    """Create standard API headers for Snyk requests."""
    return {
        "Authorization": f"token {api_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }


def get_orgs_in_group(group_id: str, api_token: str) -> List[Dict[str, Any]]:
    """
    Retrieve all organizations in a Snyk group with pagination support.
    
    Args:
        group_id: The Snyk group ID to fetch organizations from
        api_token: The Snyk API token for authentication
        
    Returns:
        List of organization data dictionaries
        
    Raises:
        requests.HTTPError: If API request fails
    """
    headers = get_api_headers(api_token)
    all_orgs = []
    url = f"https://api.snyk.io/rest/groups/{group_id}/orgs?version={API_VERSION}&limit=100"
    
    while url:
        print(f"Fetching organizations: {url}")
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            orgs = data.get("data", [])
            all_orgs.extend(orgs)
            
            # Handle pagination
            links = data.get("links", {})
            next_url = links.get("next")
            
            if next_url:
                url = f"https://api.snyk.io{next_url}" if next_url.startswith("/") else next_url
            else:
                url = None
                
        except requests.RequestException as e:
            print(f"Error fetching organizations: {e}")
            raise
    
    return all_orgs


def create_migration_data(source_orgs: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Transform source organization data into migration format.
    
    Args:
        source_orgs: List of source organization data from API
        
    Returns:
        Dictionary containing migration data structure
    """
    org_data = []
    source_orgs_data = []
    
    for org in source_orgs:
        org_attrs = org.get("attributes", {})
        org_name = org_attrs.get("name", "")
        org_id = org.get("id", "")
        
        if not org_name or not org_id:
            print(f"Warning: Skipping org with missing name or ID: {org}")
            continue
            
        # Data for creating new organizations in target group
        org_data.append({
            "name": org_name,
            "groupId": TARGET_GROUP_ID,
            "sourceOrgId": TEMPLATE_ORG_ID
        })
        
        # Source organization reference for target extraction
        source_orgs_data.append({
            "id": org_id,
            "name": org_name
        })
    
    return {
        "orgs": org_data,
        "sourceOrgs": source_orgs_data
    }


def save_migration_data(migration_data: Dict[str, List[Dict[str, Any]]], filename: str = OUTPUT_FILE) -> None:
    """
    Save migration data to JSON files in the SNYK_LOG_PATH directory.
    
    Args:
        migration_data: The migration data structure to save
        filename: Output filename for org creation data (default: OUTPUT_FILE constant)
    """
    try:
        # Create full path for output file
        output_path = os.path.join(SNYK_LOG_PATH, filename)
        source_path = os.path.join(SNYK_LOG_PATH, SOURCE_ORGS_FILE)
        
        # Save org creation data (clean format for org creation)
        org_creation_data = {"orgs": migration_data["orgs"]}
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(org_creation_data, f, indent=2, ensure_ascii=False)
        print(f"Successfully saved organization creation data to {output_path}")
        
        # Save source org data separately for target extraction
        source_data = {"sourceOrgs": migration_data["sourceOrgs"]}
        with open(source_path, "w", encoding="utf-8") as f:
            json.dump(source_data, f, indent=2, ensure_ascii=False)
        print(f"Successfully saved source organization data to {source_path}")
        
    except IOError as e:
        print(f"Error saving files: {e}")
        raise


def main() -> None:
    """Main execution function."""
    # Check for required environment variables
    source_api_token = os.getenv("SNYK_TOKEN")
    if not source_api_token:
        print("Error: SNYK_TOKEN environment variable is required")
        print("Please set it with your Snyk API token and try again")
        sys.exit(1)
    
    # Check for required configuration environment variables
    missing_vars = []
    if not TARGET_GROUP_ID:
        missing_vars.append("TARGET_GROUP_ID")
    if not SOURCE_GROUP_ID:
        missing_vars.append("SOURCE_GROUP_ID")
    if not TEMPLATE_ORG_ID:
        missing_vars.append("TEMPLATE_ORG_ID")
    if not os.getenv("SNYK_LOG_PATH"):
        missing_vars.append("SNYK_LOG_PATH")
    
    if missing_vars:
        print("Error: The following environment variables are required:")
        for var in missing_vars:
            print(f"  - {var}")
        print("\nPlease set them and try again:")
        print("  export TARGET_GROUP_ID='your-target-group-id'")
        print("  export SOURCE_GROUP_ID='your-source-group-id'")
        print("  export TEMPLATE_ORG_ID='your-template-org-id'")
        print("  export SNYK_LOG_PATH='/path/to/snyk-logs'")
        sys.exit(1)
    
    # Ensure the log directory exists
    try:
        os.makedirs(SNYK_LOG_PATH, exist_ok=True)
        print(f"Output directory: {SNYK_LOG_PATH}")
    except Exception as e:
        print(f"Error: Unable to create output directory {SNYK_LOG_PATH}: {e}")
        sys.exit(1)
    
    try:
        # Fetch source organizations
        print("Extracting organizations from source group...")
        print(f"Source Group ID: {SOURCE_GROUP_ID}")
        print(f"Target Group ID: {TARGET_GROUP_ID}")
        
        source_orgs = get_orgs_in_group(SOURCE_GROUP_ID, source_api_token)
        print(f"Found {len(source_orgs)} organizations in source group")
        
        if not source_orgs:
            print("Warning: No organizations found in source group")
            return
        
        # Transform data for migration
        migration_data = create_migration_data(source_orgs)
        
        # Save results
        save_migration_data(migration_data)
        
        # Summary
        org_count = len(migration_data["orgs"])
        source_count = len(migration_data["sourceOrgs"])
        
        print("\n=== EXTRACTION SUMMARY ===")
        print(f"Organizations to create: {org_count}")
        print(f"Source references saved: {source_count}")
        print(f"Org creation file: {os.path.join(SNYK_LOG_PATH, OUTPUT_FILE)}")
        print(f"Source data file: {os.path.join(SNYK_LOG_PATH, SOURCE_ORGS_FILE)}")
        print("Ready for organization creation step!")
        
    except Exception as e:
        print(f"Error during extraction: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
