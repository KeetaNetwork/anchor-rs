#!/bin/bash
set -eo pipefail

# Release automation script for the workspace
# This script automatically discovers workspace packages, orders them by dependencies,
# and publishes them to crates.io with proper release tagging.

# Configuration
readonly PROJECT_NAME="anchor-rs"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly MAX_DEPENDENCY_ITERATIONS=20
readonly CRATES_IO_WAIT_TIME=30
readonly ERR_RETURN_DIR="Failed to return to previous directory"

# Parse command line arguments
DRY_RUN=false
INITIAL_RELEASE=false
ALLOW_DIRTY=false
SKIP_TESTS=false
SELECTED_PACKAGES=()

show_help() {
    cat << EOF
Usage: $0 [OPTIONS] [PACKAGE...]

Release automation script for publishing workspace packages to crates.io.

Arguments:
  PACKAGE...   Optional list of workspace package names to release. When
               provided, only those packages are published (in dependency
               order). Their workspace dependencies must already be
               published.

Options:
  --dry-run     Show what would be done without actually publishing or creating tags
  --initial     Force publication of all packages, even if they appear already published
                (useful when adding new packages to an existing workspace)
  --allow-dirty Skip the clean-working-directory check and pass --allow-dirty to
                cargo publish (publishes uncommitted changes)
  --skip-tests  Skip running the test suite (make test-all) before publishing;
                lints still run
  -h, --help    Show this help message

Examples:
  $0                            # Run the full release process
  $0 --dry-run                  # Preview what would be done
  $0 --initial                  # Force publish all packages (for new workspace packages)
  $0 keetanetwork-anchor        # Release only keetanetwork-anchor
  $0 --dry-run keetanetwork-anchor keetanetwork-anchor-bindings  # Preview a subset release

The script will:
1. Discover all workspace packages automatically
2. Order them by dependencies (topological sort)
3. Validate and publish each package in order
4. Create a signed per-crate release tag (releases/<crate>/vX) with its checksum
5. Provide instructions for pushing to GitHub

Prerequisites:
- Clean git working directory (for actual release)
- jq and curl installed
- All tests and lints passing
- Proper crates.io authentication configured
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --initial)
            INITIAL_RELEASE=true
            shift
            ;;
        --allow-dirty)
            ALLOW_DIRTY=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        -*)
            echo "Unknown option: $1" >&2
            echo "Use --help for usage information" >&2
            exit 1
            ;;
        *)
            SELECTED_PACKAGES+=("$1")
            shift
            ;;
    esac
done

# Colors for output (only if terminal supports it)
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly CYAN='\033[0;36m'
    readonly NC='\033[0m' # No Color
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly BLUE=''
    readonly CYAN=''
    readonly NC=''
fi

# Logging functions with consistent formatting
log_info() {
    local message="$1"
    echo -e "${BLUE}INFO:${NC} ${message}" >&2
}

log_success() {
    local message="$1"
    echo -e "${GREEN}SUCCESS:${NC} ${message}" >&2
}

log_warning() {
    local message="$1"
    echo -e "${YELLOW}WARNING:${NC} ${message}" >&2
}

log_error() {
    local message="$1"
    echo -e "${RED}ERROR:${NC} ${message}" >&2
}

log_dry_run() {
    local message="$1"
    echo -e "${CYAN}DRY-RUN:${NC} ${message}" >&2
}

# Utility functions
die() {
    local message="$1"
    local exit_code="${2:-1}"
    log_error "$message"
    exit "$exit_code"
}

require_command() {
    local cmd="$1"
    local install_hint="${2:-}"
    
    if ! command -v "$cmd" &> /dev/null; then
        if [[ -n "$install_hint" ]]; then
            die "$cmd is required but not installed. $install_hint"
        else
            die "$cmd is required but not installed. Please install $cmd."
        fi
    fi
}

# Validation functions
validate_environment() {
    log_info "Validating environment..."
    
    # Check required tools
    require_command "jq" "Please install jq: brew install jq"
    require_command "curl" "Please install curl"
    require_command "cargo" "Please install Rust and Cargo"
    require_command "git" "Please install git"
    
    # Verify we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        die "Not in a git repository"
    fi
    
    # Check working directory cleanliness (skip in dry-run or with --allow-dirty)
    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "Skipping working directory clean check in dry-run mode"
    elif [[ "$ALLOW_DIRTY" == "true" ]]; then
        log_warning "Skipping working directory clean check (--allow-dirty)"
    elif [[ -n $(git status --porcelain) ]]; then
        log_error "Working directory is not clean. Please commit or stash changes."
        log_error "Use --allow-dirty to override."
        git status --short
        exit 1
    fi
    
    # Ensure we're in the project root
    if [[ ! -f "Cargo.toml" ]] || ! grep -q "^\[workspace\]" "Cargo.toml"; then
        die "Must be run from the workspace root directory"
    fi
}

# Git operations
get_last_crate_tag() {
    local package_name="$1"
    local tag
    tag=$(git tag -l "releases/${package_name}/v*" | sort -V | tail -1)

    # Fall back to the last workspace-wide tag from before per-crate tagging.
    if [[ -z "$tag" ]]; then
        tag=$(git tag -l "releases/v*" | sort -V | tail -1)
    fi

    echo "$tag"
}

get_commits_for_package() {
    local last_tag="$1"
    local package_dir="$2"
    if [[ -z "$last_tag" ]]; then
        # If no previous release tag, get all commits touching the package
        git log --oneline --reverse -- "$package_dir"
    else
        # Get commits touching the package since its last release tag
        git log --oneline --reverse "${last_tag}..HEAD" -- "$package_dir"
    fi
}

get_workspace_version() {
    local version
    version=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
    
    if [[ -z "$version" ]]; then
        die "Could not extract version from Cargo.toml"
    fi
    
    echo "$version"
}

# Package version resolution
resolve_package_version() {
    local package_dir="$1"
    local workspace_version="$2"
    
    # Extract version from package Cargo.toml
    local version_line
    version_line=$(grep '^version' "$package_dir/Cargo.toml" | head -1)
    
    if echo "$version_line" | grep -q "workspace = true"; then
        # Use workspace version
        echo "$workspace_version"
    else
        # Extract explicit version
        echo "$version_line" | sed 's/version = "\(.*\)"/\1/'
    fi
}

# Crates.io sparse-index functions (the API endpoint rejects requests without
# a registered User-Agent; the index does not, and carries the same data)
crate_index_url() {
    local name="$1"
    local prefix
    case ${#name} in
        1) prefix="1" ;;
        2) prefix="2" ;;
        3) prefix="3/${name:0:1}" ;;
        *) prefix="${name:0:2}/${name:2:2}" ;;
    esac
    echo "https://index.crates.io/${prefix}/${name}"
}

check_if_published() {
    local package_name="$1"
    local package_version="$2"
    
    log_info "Checking if $package_name v$package_version is already published..."
    
    local response
    response=$(curl -sf "$(crate_index_url "$package_name")" 2>/dev/null) || return 1  # Not published
    
    if echo "$response" | jq -e --arg v "$package_version" 'select(.vers==$v)' > /dev/null 2>&1; then
        return 0  # Already published
    else
        return 1  # Not published
    fi
}

get_package_checksum() {
    local package_name="$1"
    local package_version="$2"
    
    log_info "Getting checksum for $package_name v$package_version..."
    
    local response
    response=$(curl -sf "$(crate_index_url "$package_name")" 2>/dev/null) || {
        echo "ERROR"
        return 1
    }
    
    local checksum
    checksum=$(echo "$response" | jq -r --arg v "$package_version" 'select(.vers==$v) | .cksum' 2>/dev/null | tail -1)
    
    if [[ "$checksum" == "null" ]] || [[ -z "$checksum" ]]; then
        echo "ERROR"
        return 1
    fi
    
    echo "$checksum"
    return 0
}

# Package publishing functions
validate_package() {
    local package_dir="$1"
    local package_name="$2"
    local package_version="$3"
    
    log_dry_run "Validating package $package_name v$package_version from $package_dir"
    
    cd "$package_dir" || die "Failed to change to package directory: $package_dir"
    
    # First try cargo check to validate compilation
    if cargo check --all-features; then
        log_success "Compilation validation passed for $package_name v$package_version"
        
        # Then try cargo package. A sibling workspace crate being released in
        # the same run is not on crates.io yet, so tolerate only that failure.
        local package_output
        if package_output=$(cargo package --allow-dirty --all-features 2>&1); then
            log_success "Package validation passed for $package_name v$package_version"
        elif echo "$package_output" | grep -q "failed to select a version for the requirement"; then
            log_warning "Package verify for $package_name skipped: depends on a workspace crate not yet on crates.io"
        elif [[ "$INITIAL_RELEASE" == "false" ]]; then
            log_error "$package_output"
            die "Package validation failed for $package_name v$package_version"
        fi
        
        cd - > /dev/null || die "$ERR_RETURN_DIR"
        return 0
    else
        log_error "Compilation validation failed for $package_name v$package_version"
        cd - > /dev/null || die "$ERR_RETURN_DIR"
        return 1
    fi
}

publish_package() {
    local package_dir="$1"
    local package_name="$2"
    local package_version="$3"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        validate_package "$package_dir" "$package_name" "$package_version"
        return $?
    fi
    
    log_info "Publishing $package_name v$package_version..."
    
    cd "$package_dir" || die "Failed to change to package directory: $package_dir"

    local publish_args=(--all-features)
    if [[ "$ALLOW_DIRTY" == "true" ]]; then
        publish_args+=(--allow-dirty)
    fi

    if cargo publish "${publish_args[@]}"; then
        log_success "Published $package_name v$package_version"
        cd - > /dev/null || die "$ERR_RETURN_DIR"
        return 0
    else
        log_error "Failed to publish $package_name v$package_version"
        cd - > /dev/null || die "$ERR_RETURN_DIR"
        return 1
    fi
}

run_tests_and_lints() {
    if [[ "$DRY_RUN" != "true" ]]; then
        if [[ "$SKIP_TESTS" == "true" ]]; then
            log_warning "Skipping tests (--skip-tests)"
        else
            log_info "Running tests..."
            if ! make test-all; then
                die "Tests failed. Aborting release."
            fi
        fi

        log_info "Running lints..."
        if ! make do-lint; then
            die "Lints failed. Aborting release."
        fi
    elif [[ "$SKIP_TESTS" == "true" ]]; then
        log_dry_run "Would skip tests (--skip-tests)"
        log_dry_run "Would run: make do-lint"
    else
        log_dry_run "Would run: make test-all"
        log_dry_run "Would run: make do-lint"
    fi
}

# Release tag creation, one tag per published crate
create_crate_release_tag() {
    local package_name="$1"
    local package_version="$2"
    local checksum="$3"

    local tag_name="releases/${package_name}/v${package_version}"

    local last_tag
    last_tag=$(get_last_crate_tag "$package_name")

    local commit_list
    commit_list=$(get_commits_for_package "$last_tag" "$package_name")

    # Create tag message
    local tag_message="This is ${package_name} v${package_version} which has the following changes:
"

    if [[ -n "$commit_list" ]]; then
        tag_message="${tag_message}
${commit_list}"
    else
        tag_message="${tag_message}
- Initial release"
    fi

    tag_message="${tag_message}

It includes the following release artifact on crates.io:
\`\`\`
        ${package_name}@${package_version}   SHA256: ${checksum}
\`\`\`"

    if [[ -n "$last_tag" ]] && [[ -n "$commit_list" ]]; then
        tag_message="${tag_message}

**Full Changelog**:
https://github.com/KeetaNetwork/${PROJECT_NAME}/compare/${last_tag}...${tag_name}"
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_dry_run "Would create signed release tag: $tag_name"
        log_info "Tag message preview:" 
        echo "----------------------------------------" >&2
        echo "$tag_message" >&2
        echo "----------------------------------------" >&2
        return 0
    fi

    log_info "Creating signed release tag: $tag_name"

    # Create signed tag
    if git tag -s "$tag_name" -m "$tag_message"; then
        log_success "Created signed tag: $tag_name"
        return 0
    else
        log_error "Failed to create signed tag: $tag_name"
        return 1
    fi
}

# Workspace package discovery and dependency ordering
discover_workspace_packages() {
    # Use cargo metadata to get package information with dependencies
    local metadata
    metadata=$(cargo metadata --format-version 1 2>/dev/null) || die "Failed to get cargo metadata"
    
    # Get all workspace packages (filter out external dependencies)
    local workspace_packages
    workspace_packages=$(echo "$metadata" | jq -r '.workspace_members[]' | sed 's|.*/||' | sed 's|#.*||' | sort)
    
    if [[ -z "$workspace_packages" ]]; then
        die "No workspace packages found in metadata"
    fi
    
    # Convert to array
    local all_packages=()
    while IFS= read -r package; do
        if [[ -n "$package" ]]; then
            all_packages+=("$package")
        fi
    done <<< "$workspace_packages"
    
    if [[ ${#all_packages[@]} -eq 0 ]]; then
        die "No valid workspace packages found"
    fi
    
    # Topological sort based on dependencies from metadata
    topological_sort_packages "$metadata" "${all_packages[@]}"
}

topological_sort_packages() {
    local metadata="$1"
    shift
    local all_packages=("$@")
    
    local sorted_packages=()
    local remaining_packages=("${all_packages[@]}")
    local iteration=0
    
    while [[ ${#remaining_packages[@]} -gt 0 && $iteration -lt $MAX_DEPENDENCY_ITERATIONS ]]; do
        local made_progress=false
        local new_remaining=()
        
        for package in "${remaining_packages[@]}"; do
            local has_unresolved_deps=false
            
            # Get dependencies for this package from metadata
            local package_deps
            package_deps=$(echo "$metadata" | jq -r ".packages[] | select(.name==\"$package\") | .dependencies[].name" 2>/dev/null)
            
            for dep in $package_deps; do
                # Check if this dependency is a workspace package still in remaining packages
                for remaining in "${remaining_packages[@]}"; do
                    if [[ "$remaining" == "$dep" && "$remaining" != "$package" ]]; then
                        has_unresolved_deps=true
                        break 2
                    fi
                done
            done
            
            if [[ "$has_unresolved_deps" == false ]]; then
                # This package can be processed now
                sorted_packages+=("$package")
                made_progress=true
            else
                # Keep this package for next iteration
                new_remaining+=("$package")
            fi
        done
        
        remaining_packages=("${new_remaining[@]}")
        
        if [[ "$made_progress" == false ]]; then
            log_warning "Circular dependency detected or unable to resolve dependencies. Remaining packages: ${remaining_packages[*]}"
            # Add remaining packages in original order
            sorted_packages+=("${remaining_packages[@]}")
            break
        fi
        
        ((iteration++))
    done
    
    # Output the sorted packages
    printf '%s\n' "${sorted_packages[@]}"
}

# Restrict a dependency-ordered package list to the user-requested subset.
# Validates that every requested package exists and preserves the original order.
filter_selected_packages() {
    local available=("$@")
    local result=()
    local sel pkg found

    for sel in "${SELECTED_PACKAGES[@]}"; do
        found=false
        for pkg in "${available[@]}"; do
            if [[ "$pkg" == "$sel" ]]; then
                found=true
                break
            fi
        done
        if [[ "$found" == false ]]; then
            die "Requested package '$sel' is not a workspace package"
        fi
    done

    for pkg in "${available[@]}"; do
        for sel in "${SELECTED_PACKAGES[@]}"; do
            if [[ "$pkg" == "$sel" ]]; then
                result+=("$pkg")
                break
            fi
        done
    done

    printf '%s\n' "${result[@]}"
}

# Main release orchestration
process_packages() {
    local workspace_version="$1"
    shift
    local packages=("$@")
    
    local published_packages=()
    local created_tags=()
    
    # Publish each package in dependency order
    for package in "${packages[@]}"; do
        if [[ ! -d "$package" ]]; then
            log_warning "Package directory $package not found, skipping"
            continue
        fi
        
        log_info "Processing package: $package"
        
        # Resolve version (workspace or explicit)
        local version
        version=$(resolve_package_version "$package" "$workspace_version")
        
        if [[ -z "$version" ]]; then
            log_warning "Could not extract version for $package, skipping"
            continue
        fi
        
        log_info "Found $package version: $version"
        
        # Check if already published (skip check if --initial flag is used)
        if [[ "$INITIAL_RELEASE" == "true" ]]; then
            log_info "Initial release mode: forcing publication of $package v$version"
            local skip_published_check=true
        else
            local skip_published_check=false
        fi
        
        if [[ "$skip_published_check" == "false" ]] && check_if_published "$package" "$version"; then
            log_warning "$package v$version is already published, skipping"
        else
            # Publish the package
            if publish_package "$package" "$package" "$version"; then
                published_packages+=("$package@$version")
                
                local checksum
                if [[ "$DRY_RUN" != "true" ]]; then
                    # Wait for crates.io to process
                    log_info "Waiting for crates.io to process $package..."
                    sleep $CRATES_IO_WAIT_TIME
                    
                    # Get checksum for the tag message
                    if ! checksum=$(get_package_checksum "$package" "$version"); then
                        checksum="[Error retrieving checksum]"
                    fi
                else
                    log_dry_run "Would wait for crates.io to process $package"
                    log_dry_run "Would retrieve checksum for newly published $package v$version"
                    checksum="[DRY-RUN: would retrieve from crates.io after publishing]"
                fi

                # Tag the crate release
                if create_crate_release_tag "$package" "$version" "$checksum"; then
                    created_tags+=("releases/${package}/v${version}")
                elif [[ "$DRY_RUN" != "true" ]]; then
                    die "Failed to create release tag for $package v$version"
                fi
            else
                if [[ "$DRY_RUN" != "true" ]]; then
                    die "Failed to publish $package, aborting release"
                fi
            fi
        fi
    done
    
    # Output results for main function
    echo "PUBLISHED_PACKAGES:${published_packages[*]}"
    echo "CREATED_TAGS:${created_tags[*]}"
}

finalize_release() {
    local published_packages_str="$1"
    local created_tags_str="$2"
    
    # Convert strings back to arrays
    IFS=' ' read -ra published_packages <<< "$published_packages_str"
    IFS=' ' read -ra created_tags <<< "$created_tags_str"

    if [[ ${#published_packages[@]} -eq 0 ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "Dry-run: No packages would be published (everything already on crates.io)"
        else
            log_warning "No packages were published (everything already on crates.io)"
        fi
        return 0
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_success "Dry-run completed successfully!"
        log_info "Would publish packages: ${published_packages[*]}"
        if [[ ${#created_tags[@]} -gt 0 ]]; then
            log_info "Would create release tags: ${created_tags[*]}"
        fi
        log_info "To run for real: make release [--initial]"
    else
        log_success "Release process completed successfully!"
        log_info "Published packages: ${published_packages[*]}"
        if [[ ${#created_tags[@]} -gt 0 ]]; then
            log_info "Created release tags: ${created_tags[*]}"
            log_info "To push the tags to GitHub, run: git push origin ${created_tags[*]}"
        fi
    fi
}

# Main entry point
main() {
    # Initialize
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Starting release process in DRY-RUN mode..."
        log_warning "No packages will be published and no tags will be created"
    else
        log_info "Starting release process..."
    fi
    
    if [[ "$INITIAL_RELEASE" == "true" ]]; then
        log_info "Initial release mode: will force publication of all packages"
    fi
    
    # Validate environment and prerequisites
    validate_environment
    
    # Run tests and lints
    run_tests_and_lints
    
    local workspace_version
    workspace_version=$(get_workspace_version)
    
    # Discover packages and determine order
    log_info "Discovering workspace packages and dependency order..."
    local packages=()
    while IFS= read -r package; do
        if [[ -n "$package" ]]; then
            packages+=("$package")
        fi
    done < <(discover_workspace_packages)
    
    if [[ ${#packages[@]} -eq 0 ]]; then
        die "No workspace packages found"
    fi

    # Restrict to a requested subset, if any were passed on the command line.
    if [[ ${#SELECTED_PACKAGES[@]} -gt 0 ]]; then
        log_info "Restricting release to requested packages: ${SELECTED_PACKAGES[*]}"
        local filtered_packages=()
        while IFS= read -r package; do
            if [[ -n "$package" ]]; then
                filtered_packages+=("$package")
            fi
        done < <(filter_selected_packages "${packages[@]}")
        packages=("${filtered_packages[@]}")
    fi

    log_info "Package publishing order: ${packages[*]}"
    
    # Process packages and collect results
    local process_output
    process_output=$(process_packages "$workspace_version" "${packages[@]}")
    
    local published_packages_str
    local created_tags_str
    published_packages_str=$(echo "$process_output" | grep "^PUBLISHED_PACKAGES:" | cut -d: -f2-)
    created_tags_str=$(echo "$process_output" | grep "^CREATED_TAGS:" | cut -d: -f2-)
    
    # Finalize release
    finalize_release "$published_packages_str" "$created_tags_str"
}

# Run main function with all arguments
main "$@"
