# Snyk Extract and Import Tool

![Snyk OSS Example](https://raw.githubusercontent.com/snyk-labs/oss-images/main/oss-example.jpg)

This project provides scripts to extract organizations and targets (repositories) from a source Snyk tenant and import them into a target tenant. The process extracts organization data and target information from the source tenant, then recreates the organizations and imports all targets and their projects into the target tenant.

## Overview

The extraction and import tool consists of two Python scripts:
1. **`org_extraction.py`** - Extracts organization data from a source Snyk group
2. **`targets_extraction.py`** - Extracts targets (repositories) from source organizations for import into target organizations. Supports filtering by specific integration types (GitHub, GitHub Enterprise, GitHub Cloud App, or GitLab)

## Prerequisites

- Python 3.7+ (tested with Python 3.13.5)
- Snyk API tokens for both source and target tenants
- Access to both source and target Snyk groups

## Installation & Setup

### 1. Clone or Download the Project

```bash
cd /path/to/snyk-extract-and-import
```

### 2. Set Up Python Environment

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # On macOS/Linux
# or
.venv\Scripts\activate  # On Windows
```

### 3. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Configuration

### Environment Variables

Set the following environment variables before running the scripts:

```bash
export SNYK_TOKEN="your-snyk-api-token"
export GITLAB_API_TOKEN="your-gitlab-api-token"  # Required only for GitLab targets

# Required for org_extraction.py
export SOURCE_GROUP_ID="your-source-group-id"
export TARGET_GROUP_ID="your-target-group-id"
export TEMPLATE_ORG_ID="your-template-org-id"  # Organization in target group to copy settings from

# Required for all scripts - directory where files will be read from and written to
export SNYK_LOG_PATH="/path/to/snyk-logs"

# Create the log directory
mkdir -p "$SNYK_LOG_PATH"
```

**Note:** The `GITLAB_API_TOKEN` is only required when extracting GitLab targets using `--source gitlab`. The script needs this token to call the GitLab API and retrieve project IDs for proper import formatting. You can omit this token if you're only extracting GitHub-based targets.

> **📂 File Output Notice**
> 
> All generated files are automatically saved to the directory specified by the `SNYK_LOG_PATH` environment variable. Make sure this directory exists and is writable before running any scripts.

## How To Run Script

The complete extraction and import process involves 4 steps. Steps 1 & 3 use the Python scripts in this repository, while Steps 2 & 4 use Snyk's API Import Tool to actually create the organizations and import the projects.

### Step 1: Extract Organizations from Source Tenant

Extract organization data from the source tenant and prepare organization definitions for recreation in the target tenant.

**Prerequisites:**
- Set the required environment variables (see Configuration section above)

**Terminal Commands:**
```bash
# Run the extraction script
python3 org_extraction.py
```

**Output:** Creates `snyk-orgs-to-create.json` file in the `$SNYK_LOG_PATH` directory

**Important:** Keep the source default organization from the file. Make sure the target group's default organization name matches the source group's default organization name so targets map properly (names should match by default).
### Step 2: Create Organizations in Target Tenant

Use Snyk's API Import Tool to recreate the organizations in the target tenant.

**Terminal Commands:**
```bash
# Install the API Import Tool
npm install -g snyk-api-import

# Create organizations
DEBUG=snyk* snyk-api-import orgs:create --file="$SNYK_LOG_PATH/snyk-orgs-to-create.json"
```

**Output:** Generates `snyk-created-orgs.json` file in the SNYK_LOG_PATH directory

### Step 3: Extract Targets from Source Organizations

Extract targets (repositories) from the source organizations for import. You must specify which integration type to extract targets from.

**Terminal Commands:**
```bash
# Extract GitHub targets
python3 targets_extraction.py --source github

# Extract GitHub Enterprise targets
python3 targets_extraction.py --source github-enterprise

# Extract GitHub Cloud App targets
python3 targets_extraction.py --source github-cloud-app

# Extract GitLab targets
python3 targets_extraction.py --source gitlab
```


**Prerequisites:**
- `snyk-orgs-to-create.json` (from Step 1)
- `snyk-created-orgs.json` (from Step 2)
- For GitLab targets: `GITLAB_API_TOKEN` environment variable must be set

**Output:** Creates `snyk-import-targets.json` ready for import in the `$SNYK_LOG_PATH` directory

**Note:** Run the script multiple times with different `--source` values if you need to extract targets from multiple integration types. Each run will create a separate output file for that integration type.

### Step 4: Import Targets to Target Organizations

Use the API Import Tool to import all targets and create projects in the target tenant.

**Terminal Commands:**
```bash
snyk-api-import import --file="$SNYK_LOG_PATH/snyk-import-targets.json"
```

**Post-Import:** Check logs in `$SNYK_LOG_PATH` for any project import failures that may need manual attention.

## Dependencies

### Required Python Packages

- **requests** (>=2.25.0) - HTTP library for Snyk API calls

### Built-in Python Modules

- **argparse** - Command-line argument parsing (used in `targets_extraction.py`)
- **json** - JSON parsing and manipulation
- **os** - Environment variable access and file system operations
- **sys** - System operations (used in `org_extraction.py`)
- **time** - Time-related functions (used for API rate limiting)
- **typing** - Type hints support (used in `org_extraction.py`)
- **urllib.parse** - URL parsing utilities (used for GitLab API integration)

## API Permissions

Ensure your Snyk API tokens have the following permissions:

### Source Token
- Read access to source group organizations
- Read access to organization targets
- Read access to target attributes and metadata

### Target Token (for organization creation)
- Write access to target group
- Organization creation permissions

