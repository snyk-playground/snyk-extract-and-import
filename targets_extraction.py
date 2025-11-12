"""
Snyk Target Extraction Script

This script extracts targets (repositories) from source organizations in a Snyk tenant
and prepares them for import into target organizations. It handles both single and
multi-branch repositories by creating separate import entries for each branch.

Supports both GitHub and GitLab integrations:
- GitHub: Uses owner/repo format
- GitLab: Uses project ID format

The script reads from:
- snyk-orgs-to-create.json: Source organization data (from org_extraction.py)  
- snyk-created-orgs.json: Target organization mapping data

Output:
- snyk_import_targets.json: Import-ready JSON file for Snyk API import tool

Required environment variables:
- SNYK_TOKEN: Snyk API token for the source tenant
- GITLAB_API_TOKEN: GitLab API token (required only if extracting GitLab targets)
- SNYK_LOG_PATH: Directory path where input/output files are located

Usage:
    export SNYK_TOKEN="your-source-token"
    export GITLAB_API_TOKEN="your-gitlab-token"  # Only needed for GitLab targets
    export SNYK_LOG_PATH="/path/to/snyk-logs"
    
    # Extract GitHub targets
    python targets_extraction.py --source github
    
    # Extract GitHub Enterprise targets
    python targets_extraction.py --source github-enterprise
    
    # Extract GitHub Cloud App targets
    python targets_extraction.py --source github-cloud-app
    
    # Extract only GitLab targets  
    python targets_extraction.py --source gitlab
"""

import json
import os
import requests
import argparse
import time
import urllib.parse


# Configuration
SOURCE_API_TOKEN = os.getenv("SNYK_TOKEN")
GITLAB_API_TOKEN = os.getenv("GITLAB_API_TOKEN")
SNYK_LOG_PATH = os.getenv("SNYK_LOG_PATH", ".")  # Default to current directory if not set
API_VERSION = "2024-06-18"
API_BASE_URL = "https://api.snyk.io"
GITLAB_BASE_URL = "https://gitlab.com"
PAGINATION_LIMIT = 100

# File paths (will be combined with SNYK_LOG_PATH)
TARGET_ORG_MAPPING_FILE = "snyk-created-orgs.json"
SOURCE_ORGS_FILE = "snyk-source-orgs.json"
OUTPUT_FILE = "snyk-import-targets.json"

# GitHub integration types (in order of preference)
GITHUB_INTEGRATION_TYPES = ["github-cloud-app", "github-enterprise", "github"]

# GitLab integration types (in order of preference)
GITLAB_INTEGRATION_TYPES = ["gitlab"]


def get_targets_for_org(org_id, api_token):
    """
    Get all targets for an organization with pagination support.
    
    Args:
        org_id (str): The organization ID
        api_token (str): Snyk API token
        
    Returns:
        list: List of all targets for the organization
    """
    headers = {
        "Authorization": f"token {api_token}",
        "Content-Type": "application/json"
    }
    
    all_targets = []
    url = f"{API_BASE_URL}/rest/orgs/{org_id}/targets?version={API_VERSION}&limit={PAGINATION_LIMIT}"
    
    while url:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        targets = data.get("data", [])
        all_targets.extend(targets)
        
        # Check for next page
        links = data.get("links", {})
        next_url = links.get("next")
        
        if next_url:
            url = f"{API_BASE_URL}{next_url}" if next_url.startswith("/") else next_url
        else:
            url = None
    
    return all_targets


def get_projects_for_target(org_id, target_id, api_token):
    """
    Get all projects for a specific target with pagination support.
    
    Args:
        org_id (str): The organization ID
        target_id (str): The target ID
        api_token (str): Snyk API token
        
    Returns:
        list: List of all projects for the target
    """
    headers = {
        "Authorization": f"token {api_token}",
        "Content-Type": "application/json"
    }
    
    all_projects = []
    url = f"{API_BASE_URL}/rest/orgs/{org_id}/projects?target_id={target_id}&version={API_VERSION}&limit={PAGINATION_LIMIT}"
    
    while url:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        projects = data.get("data", [])
        all_projects.extend(projects)
        
        # Check for next page
        links = data.get("links", {})
        next_url = links.get("next")
        
        if next_url:
            url = f"{API_BASE_URL}{next_url}" if next_url.startswith("/") else next_url
        else:
            url = None
    
    return all_projects


def get_target_org_mapping():
    """
    Load the mapping of source org names to target org data from SNYK_LOG_PATH.
    
    Returns:
        dict: Mapping of source org names to target org info
    """
    try:
        mapping_file_path = os.path.join(SNYK_LOG_PATH, TARGET_ORG_MAPPING_FILE)
        with open(mapping_file_path, "r") as f:
            created_orgs = json.load(f)
        
        orgs_data = created_orgs.get("orgData", [])
        org_mapping = {}
        
        for org in orgs_data:
            if isinstance(org, dict) and "origName" in org and "id" in org:
                org_mapping[org["origName"]] = {
                    "orgId": org["id"],
                    "integrations": org.get("integrations", {})
                }
                
        return org_mapping
        
    except FileNotFoundError:
        print(f"ERROR: {TARGET_ORG_MAPPING_FILE} not found.")
        print("Please run the organization creation script first to generate this file.")
        return {}


def get_source_orgs_from_json():
    """
    Load source organization data from the source organizations JSON file in SNYK_LOG_PATH.
    
    Returns:
        list: List of source organization data
    """
    try:
        source_file_path = os.path.join(SNYK_LOG_PATH, SOURCE_ORGS_FILE)
        with open(source_file_path, "r") as f:
            data = json.load(f)
        return data.get("sourceOrgs", [])
        
    except FileNotFoundError:
        print(f"ERROR: {source_file_path} not found.")
        print("Please run org_extraction.py first to generate this file.")
        return []


def extract_target_attributes_from_projects(projects):
    """
    Extract target-level attributes from projects (branch information).
    
    Args:
        projects (list): List of project data from Snyk API
        
    Returns:
        dict: Dictionary containing branch information for the target
    """
    if not projects:
        return {}
    
    print(f"        Analyzing {len(projects)} projects for this target")
    
    branches = set()
    
    for project in projects:
        project_attrs = project.get("attributes", {})
        project_name = project_attrs.get("name", "")
        
        # Extract branch from multiple possible sources
        branch = None
        
        # Priority order: target_reference, branch field, project name patterns
        if project_attrs.get("target_reference"):
            branch = project_attrs["target_reference"]
        elif project_attrs.get("branch"):
            branch = project_attrs["branch"]
        elif ":" in project_name:
            # Pattern: "repo:branch"
            potential_branch = project_name.split(":")[-1].strip()
            if potential_branch and "/" not in potential_branch:  # Avoid URLs
                branch = potential_branch
        elif " (" in project_name and ")" in project_name:
            # Pattern: "repo (branch)"
            potential_branch = project_name.split(" (")[1].split(")")[0].strip()
            if potential_branch:
                branch = potential_branch
        
        if branch:
            branches.add(branch)
            print(f"          Project '{project_name}' -> branch: {branch}")
    
    # Determine target attributes based on branch information
    target_attributes = {}
    
    if branches:
        print(f"        Found branches: {', '.join(sorted(branches))}")
        
        if len(branches) == 1:
            # Single branch case
            target_attributes["branch"] = list(branches)[0]
        else:
            # Multiple branches case - create info for separate entries
            sorted_branches = sorted(branches)
            
            # Determine primary branch
            if "main" in branches:
                primary_branch = "main"
            elif "master" in branches:
                primary_branch = "master"
            else:
                primary_branch = sorted_branches[0]
            
            target_attributes["branches"] = sorted_branches
            target_attributes["primary_branch"] = primary_branch
            
            print(f"        Multiple branches detected - will create separate import entries for each")
            print(f"        Primary branch: {primary_branch}, Other branches: {', '.join([b for b in sorted_branches if b != primary_branch])}")
    
    return target_attributes


def extract_gitlab_project_info_from_display_name(display_name):
    """
    Extract GitLab project information from display name.
    GitLab targets in Snyk have display names in the format: namespace/project
    
    Args:
        display_name (str): The display name from Snyk target (e.g., "bc_group1/inkscape-brooke")
        
    Returns:
        dict: GitLab project info with namespace and name, or None if invalid format
    """
    if not display_name or "/" not in display_name:
        return None
    
    parts = display_name.split("/")
    if len(parts) >= 2:
        # Handle nested groups: group/subgroup/project -> use last part as project name
        namespace = "/".join(parts[:-1])  # Everything except the last part
        project_name = parts[-1]         # Last part is the project name
        
        return {
            "namespace": namespace,
            "name": project_name
        }
    
    return None


def get_gitlab_project_id(gitlab_project_info, display_name):
    """
    Get GitLab project ID from GitLab API using namespace and project name.
    Includes proper rate limiting and retry logic.
    
    Args:
        gitlab_project_info (dict): Project info with namespace and name
        display_name (str): Original display name for logging
        
    Returns:
        int: GitLab project ID if found, None otherwise
        
    Rate Limiting:
        - Monitors RateLimit-Remaining header and adds delays when low
        - Handles 429 (rate limit exceeded) with exponential backoff
        - Retries up to 3 times with increasing delays
    """
    if not GITLAB_API_TOKEN:
        print(f"    WARNING: GITLAB_API_TOKEN not set, cannot get project ID for {display_name}")
        return None
    
    namespace = gitlab_project_info["namespace"]
    project_name = gitlab_project_info["name"]
    
    # URL encode the project path (namespace/project)
    project_path = f"{namespace}/{project_name}"
    encoded_path = urllib.parse.quote(project_path, safe='')
    
    headers = {
        "Authorization": f"Bearer {GITLAB_API_TOKEN}",
        "Content-Type": "application/json"
    }
    
    url = f"{GITLAB_BASE_URL}/api/v4/projects/{encoded_path}"
    
    # Retry logic for rate limiting
    max_retries = 3
    base_delay = 1  # Start with 1 second delay
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers)
            
            # Check rate limit headers
            rate_limit_remaining = response.headers.get('RateLimit-Remaining')
            if rate_limit_remaining and int(rate_limit_remaining) < 10:
                print(f"    GitLab API rate limit low ({rate_limit_remaining} remaining), adding delay...")
                time.sleep(2)
            
            if response.status_code == 200:
                project_data = response.json()
                project_id = project_data.get("id")
                print(f"    Found GitLab project ID {project_id} for {display_name}")
                return project_id
                
            elif response.status_code == 404:
                print(f"    WARNING: GitLab project not found: {display_name}")
                return None
                
            elif response.status_code == 429:  # Rate limit exceeded
                retry_after = int(response.headers.get('Retry-After', base_delay * (2 ** attempt)))
                print(f"    GitLab rate limit exceeded for {display_name}, retrying in {retry_after}s (attempt {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:  # Don't sleep on last attempt
                    time.sleep(retry_after)
                    continue
                else:
                    print(f"    ERROR: GitLab rate limit exceeded, max retries reached for {display_name}")
                    return None
                    
            else:
                print(f"    WARNING: GitLab API error {response.status_code} for {display_name}")
                if attempt < max_retries - 1:  # Retry on other errors too
                    delay = base_delay * (2 ** attempt)
                    print(f"    Retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue
                return None
                
        except Exception as e:
            print(f"    WARNING: Error calling GitLab API for {display_name}: {e}")
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                print(f"    Retrying in {delay}s (attempt {attempt + 1}/{max_retries})")
                time.sleep(delay)
                continue
            return None
    
    return None


def get_source_integration_type(target):
    """
    Get the source integration type from the target data.
    
    Args:
        target (dict): Target data from Snyk API
        
    Returns:
        str: Source integration type ('github', 'github-cloud-app', 'github-enterprise', 'gitlab') or None
    """
    # Try to get from target URL
    target_attrs = target.get("attributes", {})
    url = target_attrs.get("url", "")
    
    if "gitlab.com" in url or "gitlab" in url:
        return "gitlab"
    elif "github.com" in url:
        # For GitHub, we can't easily distinguish between integration types from URL alone
        # Default to 'github' - the filtering will be done by matching available integrations
        return "github"
    
    # Try to get from relationships (if available)
    relationships = target.get("relationships", {})
    integration = relationships.get("integration", {})
    integration_data = integration.get("data", {})
    integration_attrs = integration_data.get("attributes", {})
    
    if "integration_type" in integration_attrs:
        integration_type = integration_attrs["integration_type"]
        if integration_type in ["github", "github-cloud-app", "github-enterprise"]:
            return integration_type
        elif integration_type == "gitlab":
            return "gitlab"
    
    # Fallback: assume GitHub if display name has slash format
    display_name = target_attrs.get("display_name", "")
    if "/" in display_name:
        return "github"  # Default assumption for GitHub-like format
    
    return None


def get_integration_type_and_id(target_integrations, source_integration_type=None):
    """
    Determine the integration type (GitHub or GitLab) and get the integration ID.
    
    Args:
        target_integrations (dict): Dictionary of integrations for the target org
        source_integration_type (str): The specific integration type to match
        
    Returns:
        tuple: (integration_type, integration_id) or (None, None) if not found
    """
    # If specific integration type is requested, try to match it exactly
    if source_integration_type and source_integration_type in target_integrations:
        # For GitHub variants, normalize the type to 'github' for target formatting
        if source_integration_type in ["github", "github-cloud-app", "github-enterprise"]:
            return "github", target_integrations[source_integration_type]
        elif source_integration_type == "gitlab":
            return "gitlab", target_integrations[source_integration_type]
    
    # Fallback to original priority order if no specific type requested or not found
    # Check for GitHub integrations first
    for integration_type in GITHUB_INTEGRATION_TYPES:
        if integration_type in target_integrations:
            return "github", target_integrations[integration_type]
    
    # Check for GitLab integrations
    for integration_type in GITLAB_INTEGRATION_TYPES:
        if integration_type in target_integrations:
            return "gitlab", target_integrations[integration_type]
    
    return None, None


def create_target_entry(target_org_id, integration_id, target_info, branch=None, integration_type="github"):
    """
    Create a target entry for the import JSON.
    
    Args:
        target_org_id (str): Target organization ID
        integration_id (str): Integration ID (GitHub or GitLab)
        target_info (dict): Target information (name, owner for GitHub; id for GitLab)
        branch (str, optional): Branch name
        integration_type (str): Type of integration ("github" or "gitlab")
        
    Returns:
        dict: Target entry for import
    """
    target_data = {
        "orgId": target_org_id,
        "integrationId": integration_id,
        "exclusionGlobs": ""  # Required by import schema
    }
    
    if target_info:
        target_data["target"] = target_info.copy()
        if branch:
            target_data["target"]["branch"] = branch
    
    return target_data



def extract_targets(source_filter):
    """
    Main function to extract targets from source orgs and prepare for import.
    
    Args:
        source_filter (str): Filter for source integration type ('github', 'github-enterprise', 'github-cloud-app', or 'gitlab')
    """
    print("=== Snyk Target Extraction Script ===")
    print(f"Filtering for source integration type: {source_filter}")
    
    if not SOURCE_API_TOKEN:
        print("ERROR: SNYK_TOKEN environment variable is not set.")
        print("Please set it with your Snyk API token:")
        print("  export SNYK_TOKEN='your-token-here'")
        return
    
    if not os.getenv("SNYK_LOG_PATH"):
        print("ERROR: SNYK_LOG_PATH environment variable is not set.")
        print("Please set it to the directory containing your Snyk files:")
        print("  export SNYK_LOG_PATH='/path/to/snyk-logs'")
        return
    
    # Ensure the log directory exists and is accessible
    try:
        os.makedirs(SNYK_LOG_PATH, exist_ok=True)
        print(f"Using log directory: {SNYK_LOG_PATH}")
    except Exception as e:
        print(f"ERROR: Unable to access log directory {SNYK_LOG_PATH}: {e}")
        return
    
    # Load target organization mapping
    target_org_mapping = get_target_org_mapping()
    if not target_org_mapping:
        print("No target org mapping found.")
        return
    
    # Load source organization data
    print("Loading source organizations from saved data...")
    all_source_orgs = get_source_orgs_from_json()
    if not all_source_orgs:
        print("No source org data found. Make sure to run org_extraction.py first.")
        return
    
    # Filter to only orgs that have target mappings
    source_orgs_to_process = []
    for source_org in all_source_orgs:
        source_org_name = source_org["name"]
        if source_org_name in target_org_mapping:
            source_orgs_to_process.append({
                "id": source_org["id"],
                "attributes": {"name": source_org_name}
            })
    
    print(f"Processing {len(source_orgs_to_process)} orgs (filtered from {len(all_source_orgs)} total)")
    
    all_targets = []
    
    # Process each source organization
    for source_org in source_orgs_to_process:
        source_org_id = source_org["id"]
        source_org_name = source_org["attributes"]["name"]
        
        target_org_data = target_org_mapping.get(source_org_name)
        if not target_org_data:
            print(f"WARNING: No target org found for '{source_org_name}', skipping...")
            continue
        
        target_org_id = target_org_data["orgId"]
        target_integrations = target_org_data["integrations"]
        
        print(f"\nProcessing org: {source_org_name} -> {target_org_id}")
        
        try:
            # Get targets from the organization
            targets = get_targets_for_org(source_org_id, SOURCE_API_TOKEN)
            print(f"  Found {len(targets)} targets")
            
            # Process each target
            for target in targets:
                target_attrs = target.get("attributes", {})
                target_id = target.get("id")
                
                # Get display name - this contains owner/repo information
                display_name = target_attrs.get("display_name", "")
                
                # Get source integration type and filter if needed
                source_integration_type = get_source_integration_type(target)
                
                # Apply source filter - for GitHub types, also check if the specific integration is available
                if source_filter in ["github", "github-cloud-app", "github-enterprise"]:
                    # For GitHub variants, check if target is GitHub and if the specific integration is available
                    if source_integration_type not in ["github", "github-cloud-app", "github-enterprise"]:
                        print(f"  Skipping target: {display_name} (source: {source_integration_type}, filter: {source_filter})")
                        continue
                    # Check if the specific GitHub integration type is available in target org
                    if source_filter not in target_integrations:
                        print(f"  Skipping target: {display_name} (integration {source_filter} not available in target org)")
                        continue
                elif source_filter == "gitlab":
                    if source_integration_type != "gitlab":
                        print(f"  Skipping target: {display_name} (source: {source_integration_type}, filter: {source_filter})")
                        continue
                    # Check if GitLab integration is available in target org
                    if "gitlab" not in target_integrations:
                        print(f"  Skipping target: {display_name} (GitLab integration not available in target org)")
                        continue
                
                print(f"  Processing target: {display_name} (source: {source_integration_type})")
                
                # Find integration - prioritize the requested source filter
                integration_type, integration_id = get_integration_type_and_id(target_integrations, source_filter)
                
                if not integration_id:
                    print(f"    WARNING: No supported integration found for org {source_org_name}")
                    print(f"    Available integrations: {list(target_integrations.keys())}")
                    continue
                
                print(f"    Using {integration_type} integration: {integration_id}")
                
                # Parse target information based on integration type
                target_info = {}
                if integration_type == "github":
                    # GitHub format: owner/repo
                    if display_name and "/" in display_name:
                        owner, name = display_name.split("/", 1)
                        target_info["owner"] = owner
                        target_info["name"] = name
                    elif display_name and display_name != "unknown":
                        target_info["name"] = display_name
                elif integration_type == "gitlab":
                    # GitLab format: project ID (need to get from GitLab API)
                    gitlab_project_info = extract_gitlab_project_info_from_display_name(display_name)
                    if gitlab_project_info:
                        # Get project ID from GitLab API
                        project_id = get_gitlab_project_id(gitlab_project_info, display_name)
                        if project_id:
                            target_info["id"] = project_id
                        else:
                            print(f"    WARNING: Could not get GitLab project ID for: {display_name}")
                            continue
                    else:
                        print(f"    WARNING: Could not parse GitLab project info from display_name: {display_name}")
                        continue
                
                # Get project information to extract branch data
                try:
                    projects = get_projects_for_target(source_org_id, target_id, SOURCE_API_TOKEN)
                    project_attributes = extract_target_attributes_from_projects(projects)
                    
                except Exception as e:
                    print(f"    Warning: Could not fetch projects for target {target_id}: {e}")
                    project_attributes = {}
                
                # Create target entries based on branch information
                if project_attributes:
                    if "branch" in project_attributes:
                        # Single branch case
                        target_entry = create_target_entry(
                            target_org_id, 
                            integration_id, 
                            target_info, 
                            project_attributes["branch"],
                            integration_type
                        )
                        all_targets.append(target_entry)
                        
                        if integration_type == "github":
                            repo_info = f"{target_info.get('owner', '')}/{target_info.get('name', display_name or 'unknown')}"
                        else:  # gitlab
                            repo_info = f"GitLab Project ID: {target_info.get('id', 'unknown')}"
                        print(f"    Added target: {repo_info} (branch: {project_attributes['branch']})")
                        
                    else:  # Multiple branches case
                        branches = project_attributes["branches"]
                        primary_branch = project_attributes.get("primary_branch")
                        
                        for branch in branches:
                            target_entry = create_target_entry(
                                target_org_id, 
                                integration_id, 
                                target_info, 
                                branch,
                                integration_type
                            )
                            all_targets.append(target_entry)
                            
                            if integration_type == "github":
                                repo_info = f"{target_info.get('owner', '')}/{target_info.get('name', display_name or 'unknown')}:{branch}"
                            else:  # gitlab
                                repo_info = f"GitLab Project ID: {target_info.get('id', 'unknown')}:{branch}"
                            primary_note = " (primary)" if branch == primary_branch else ""
                            print(f"    Added target: {repo_info}{primary_note}")
                
                else:
                    # Target has no projects - add it without branch information
                    target_entry = create_target_entry(
                        target_org_id, 
                        integration_id, 
                        target_info,
                        None,
                        integration_type
                    )
                    all_targets.append(target_entry)
                    
                    if integration_type == "github":
                        repo_info = f"{target_info.get('owner', '')}/{target_info.get('name', display_name or 'unknown')}"
                        # Warning for potential import issues
                        if not target_info.get("owner") or not target_info.get("name"):
                            print(f"    ⚠️  WARNING: Target may fail import - missing owner/name: {target_entry}")
                    else:  # gitlab
                        repo_info = f"GitLab Project ID: {target_info.get('id', 'unknown')}"
                        # Warning for potential import issues
                        if not target_info.get("id"):
                            print(f"    ⚠️  WARNING: Target may fail import - missing project ID: {target_entry}")
                    
                    print(f"    Added target: {repo_info} (no projects/branches)")
                        
        except Exception as e:
            error_msg = f"Error processing org {source_org_name}: {e}"
            print(error_msg)
    
    # Save results to JSON file
    result = {"targets": all_targets}
    
    output_path = os.path.join(SNYK_LOG_PATH, OUTPUT_FILE)
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"\nExtraction complete!")
    print(f"Total targets extracted: {len(all_targets)}")
    print(f"Results saved to: {output_path}")




def main():
    """
    Main entry point for the target extraction script.
    """
    parser = argparse.ArgumentParser(
        description="Extract targets from source Snyk organizations for import",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python targets_extraction.py --source github
  python targets_extraction.py --source github-cloud-app
  python targets_extraction.py --source github-enterprise
  python targets_extraction.py --source gitlab
        """
    )
    
    parser.add_argument(
        "--source",
        choices=["github", "github-enterprise", "github-cloud-app", "gitlab"],
        required=True,
        help="Source integration type to extract targets for"
    )
    
    args = parser.parse_args()
    
    try:
        extract_targets(args.source)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"Error: {e}")
        print("Please check your configuration and try again.")


if __name__ == "__main__":
    main()