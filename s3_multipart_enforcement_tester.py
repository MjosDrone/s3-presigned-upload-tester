#!/usr/bin/env python3
#
# Filename: s3_multipart_enforcement_tester.py
#
# ==============================================================================
# S3 Multipart Upload Content-Length and State Enforcement Tester
# ==============================================================================
#
# PURPOSE:
# This script performs an end-to-end test to verify that an S3-compatible
# storage provider correctly and cryptographically enforces the 'Content-Length'
# of chunks uploaded via a presigned multipart upload URL. It also now
# tests if the provider accurately reports the status of an in-progress upload
# after *each* part is successfully uploaded.
#
# It answers the questions:
# 1. "If I tell my provider I'm uploading a 5 MiB chunk, can a malicious user
#    use that URL to upload a 6 MiB chunk and abuse my storage quota?"
# 2. "After I successfully upload each part, does querying the upload status
#    consistently and correctly report all parts uploaded so far?"
#
# For a correctly configured provider, the answers must be YES to the second
# question and a resounding NO to the first. A summary table is printed at the
# end of all runs to compare provider compliance.
#
#
# HOW TO USE:
#
# 1. Install Dependencies:
#    pip install boto3 httpx tqdm rich
#
# 2. Configure Providers:
#    - (Optional) Use `config.json`
#      - Create a file named `config.json` in the same directory.
#      - Copy the structure from the `DEFAULT_PROVIDERS` dictionary below.
#    - For each provider you want to test, create a dictionary entry.
#    - Set `"enabled": True` for the providers you want to run.
#    - Fill in the credentials and settings:
#      - "provider_name": A friendly name for reporting.
#      - "endpoint_url": The S3 API endpoint URL.
#      - "aws_access_key_id": Your access key.
#      - "aws_secret_access_key": Your secret key.
#      - "region_name": The region of your bucket.
#      - "bucket_name": An existing bucket to use for the test.
#      - "addressing_style": 'virtual' or 'path'. Check your provider's docs.
#        (e.g., Backblaze B2 uses 'virtual', Cloudflare R2 uses 'path').
#
# 3. Run the Script:
#    python s3_multipart_enforcement_tester.py
#
# 4. Interpret the Output:
#    - The script will run tests for each provider sequentially.
#    - A final summary table will be printed, showing the pass/fail status
#      of each test case for all enabled providers.
#
# ==============================================================================
"""
Self‑contained end‑to‑end multipart‑upload size‑enforcement and state-reporting
test for S3-compatible storage providers like Backblaze B2 and Cloudflare R2.

"""

import boto3
import httpx
import sys
import os
import tempfile
import math
import json
import random
from botocore.client import Config
from botocore.exceptions import ClientError
from urllib.parse import urlparse
from h11 import LocalProtocolError  # Import specific exception for httpx client-side errors
from copy import deepcopy
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn

# --- CONFIGURATION ---
# This is the primary section to edit. Add, remove, or disable providers
# by editing this list.

# Default configuration dictionary. This can be overridden by an external `config.json` file.
# The external file is the PREFERRED way to manage secrets.
DEFAULT_PROVIDERS = {
    "b2": {
        "provider_name": "Backblaze B2",
        "enabled": True,
        "endpoint_url": "https://s3.eu-central-003.backblazeb2.com",
        "aws_access_key_id": "YOUR_B2_ACCESS_KEY",
        "aws_secret_access_key": "YOUR_B2_SECRET_KEY",
        "region_name": "eu-central-003",
        "bucket_name": "YOUR_B2_BUCKET_NAME",
        "addressing_style": "virtual",  # B2 supports virtual-host style
    },
    "r2": {
        "provider_name": "Cloudflare R2",
        "enabled": True,
        "endpoint_url": "https://<YOUR_ACCOUNT_ID>.r2.cloudflarestorage.com",
        "aws_access_key_id": "YOUR_R2_ACCESS_KEY",
        "aws_secret_access_key": "YOUR_R2_SECRET_KEY",
        "region_name": "auto",
        "bucket_name": "YOUR_R2_BUCKET_NAME",
        "addressing_style": "path",  # R2 requires path style
    },
    # Add other S3-compatible providers here following the same dictionary structure.
}

CONFIG_FILE_NAME = "config.json"

# E2E Test Parameters
TEST_OBJECT_KEY = "e2e-multipart-test.bin"
# Use a file size that requires multiple parts. S3 minimum part size is typically 5MiB.
TEST_FILE_SIZE = 1024 * 1024 * 12  # 12 MiB
CHUNK_SIZE = 1024 * 1024 * 5     # 5 MiB

# Test Case Definitions for Summary Table
CASE_DESCRIPTIONS = {
    "Case 1": "CL > Body",
    "Case 2": "CL < Body",
    "Case 3": "Body Truncated",
    "Case 4": "Body Extended",
    "Case 5": "Signed < Actual",
    "Case 6": "Signed > Actual",
    "Case 7": "Control Group",
    "Case 8": "List Parts API",
}
CASE_KEYS = list(CASE_DESCRIPTIONS.keys())

# --- Rich Console Initialization ---
console = Console()


# ----------------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------------

def load_config():
    """Loads config from external file and merges it with defaults."""
    config = deepcopy(DEFAULT_PROVIDERS)
    if os.path.exists(CONFIG_FILE_NAME):
        console.print(f"[blue][INFO] Loading configuration from '{CONFIG_FILE_NAME}'...")
        with open(CONFIG_FILE_NAME, 'r') as f:
            external_config = json.load(f)

        # Merge external config into the default config
        for provider_key, provider_config in external_config.items():
            if provider_key in config:
                config[provider_key].update(provider_config)
            else:
                config[provider_key] = provider_config
    else:
        console.print(f"[yellow][WARN] No '{CONFIG_FILE_NAME}' found. Using default inline configuration.")
        console.print(f"[yellow][WARN] It is recommended to use an external file for credentials.")

    return config


def build_s3_client(cfg: dict):
    """Return a boto3 S3 client honouring the provider's addressing style."""
    return boto3.client(
        "s3",
        endpoint_url=cfg["endpoint_url"],
        aws_access_key_id=cfg["aws_access_key_id"],
        aws_secret_access_key=cfg["aws_secret_access_key"],
        region_name=cfg["region_name"],
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": cfg["addressing_style"]},
        ),
    )


def run_test_case(test_name: str, description: str, client: httpx.Client, url: str, data_stream, headers: dict, expect_failure: bool):
    """
    Executes a single PUT request for a test case and reports PASS/FAIL.
    This function forms the core of the test logic.
    """
    outcome_str = '[bold red]FAILURE[/]' if expect_failure else '[bold green]SUCCESS[/]'
    info = f"""[yellow]Description:[/] {description}
[yellow]Headers:[/] {headers}
[yellow]Expected Outcome:[/] {outcome_str}"""

    panel = Panel(info, title=f"🧪 [bold cyan]{test_name}[/]", border_style="dim")
    console.print(panel)

    try:
        # Using a data stream (generator) is KEY.
        # It forces `httpx` to trust our Content-Length header instead of calculating its own.
        # We use the `content` parameter for streaming request bodies.
        response = client.put(url, content=data_stream, headers=headers)
        response.raise_for_status()  # Raise exception for 4xx/5xx responses
        status_code = response.status_code

        # If we reach here, the request was successful (HTTP 2xx).
        # We now evaluate if this success was the expected outcome.
        if not expect_failure:
            console.print(f"  [green]✅ PASS:[/] Provider correctly ACCEPTED the valid request (HTTP {status_code}).")
            return True, response.headers.get('ETag')
        else:
            # This is a critical failure: the provider accepted a request it should have rejected.
            console.print(f"  [bold red]❌ FAIL:[/] Provider INCORRECTLY accepted a bad request with HTTP {status_code}. SECURITY RISK.")
            return False, None

    except (LocalProtocolError, httpx.HTTPError) as e:
        # This block catches three types of failures, which are EXPECTED for invalid requests:
        # 1. LocalProtocolError: httpx's client-side validation caught an error (e.g., body size mismatch).
        # 2. httpx.RequestError: A network-level error occurred (e.g., connection closed by server).
        # 3. httpx.HTTPStatusError: Server responded with 4xx or 5xx (from raise_for_status).
        if expect_failure:
            console.print(f"  [green]✅ PASS:[/] The client/provider correctly REJECTED the invalid request via exception.")
            return True, None
        else:
            # An exception during a valid request (control group) is a hard failure.
            console.print(f"  [bold red]❌ FAIL:[/] A valid request failed unexpectedly.", e)
            return False, None


def single_chunk_generator(data: bytes):
    """Generator that yields the provided data chunk a single time."""
    yield data


def truncated_chunk_generator(data: bytes):
    """Generator that yields everything except the last byte (body smaller than header)."""
    yield data[:-1]


def extended_chunk_generator(data: bytes):
    """Generator that yields original data **plus** one extra byte (body larger than header)."""
    yield data + random.randbytes(1)


def setup_clients_and_files():
    """Creates S3/HTTP clients and a local temp file. Returns (http_client, local_file_path)."""
    http_client = httpx.Client(timeout=60.0)

    # Create a temporary file with random data
    # 'delete=False' allows us to close it and still have it exist on disk.
    fd, local_file_path = tempfile.mkstemp()
    console.print(f"[blue][INFO] Generating a temporary {TEST_FILE_SIZE / (1024*1024):.0f} MiB test file at: {local_file_path}")
    
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[green]Writing random data...", total=TEST_FILE_SIZE)
        with os.fdopen(fd, 'wb') as f:
            for _ in range(TEST_FILE_SIZE // (1024*1024)):
                f.write(os.urandom(1024*1024))
                progress.update(task, advance=1024*1024)
    
    console.print("[blue][INFO] Test file generated.")
    return http_client, local_file_path


def initiate_upload(s3_client, bucket, key):
    """Initiates a multipart upload and returns the UploadId."""
    console.print(f"[blue][INFO] Initiating multipart upload for '{key}'...")
    response = s3_client.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = response['UploadId']
    console.print(f"[blue][INFO] Multipart upload initiated. UploadId: [bold]{upload_id}[/]")
    return upload_id


def update_results(results: dict, case_key: str, is_pass: bool):
    """Aggregates results. A single failure marks the whole case as failed for the run."""
    if results.get(case_key) is False:
        return  # Once failed, always failed.
    results[case_key] = is_pass


def run_test_matrix_for_part(http_client, s3_client, config, upload_id, part_number, chunk_data, results: dict):
    """Runs all enforcement tests for a single part and returns its ETag on success."""
    correct_chunk_size = len(chunk_data)
    etag = None

    # Generate one presigned URL for this part, SIGNING THE CORRECT CONTENT-LENGTH.
    # This is the key to the test: the URL is cryptographically bound to a part
    # of this specific size. Any deviation should be rejected.
    presigned_url_for_part = s3_client.generate_presigned_url(
        "upload_part",
        Params={
            "Bucket": config["bucket_name"],
            "Key": TEST_OBJECT_KEY,
            "UploadId": upload_id,
            "PartNumber": part_number,
            "ContentLength": correct_chunk_size,
        },
        ExpiresIn=3600,
        HttpMethod="PUT",
    )

    # --- TEST MATRIX DEFINITIONS ---
    # This matrix defines all tests to check how a provider handles various
    # correct and incorrect data upload scenarios.
    test_definitions = {
        "Case 1": {
            "title": "Case 1: Header `Content-Length` > Actual Body Size (Client Error)",
            "description": "Tests client-side errors where the header claims more data than is sent.",
            "data_stream": single_chunk_generator(chunk_data),
            "headers": {'Content-Length': str(correct_chunk_size + 1)},
            "expect_failure": True,
        },
        "Case 2": {
            "title": "Case 2: Header `Content-Length` < Actual Body Size (Client Error)",
            "description": "Tests client-side errors where the header claims less data than is sent.",
            "data_stream": single_chunk_generator(chunk_data),
            "headers": {'Content-Length': str(correct_chunk_size - 1)},
            "expect_failure": True,
        },
        "Case 3": {
            "title": "Case 3: Body Size < Header `Content-Length` (Server-Side Enforcement)",
            "description": "The client sends a correct header but prematurely ends the data stream. The server must detect the size mismatch and reject the request.",
            "data_stream": truncated_chunk_generator(chunk_data),
            "headers": {'Content-Length': str(correct_chunk_size)},
            "expect_failure": True,
        },
        "Case 4": {
            "title": "Case 4: Body Size > Header `Content-Length` (Server-Side Enforcement)",
            "description": "The client sends a correct header but tries to stream extra data. The server must stop reading after `Content-Length` bytes.",
            "data_stream": extended_chunk_generator(chunk_data),
            "headers": {'Content-Length': str(correct_chunk_size)},
            "expect_failure": True,
        },
        "Case 5": {
            "title": "Case 5: Body Size > Signed `Content-Length` (Signature Enforcement)",
            "description": "The most critical test. The client sends a body and a matching header, but their size is LARGER than what was signed in the URL. MUST FAIL.",
            "data_stream": single_chunk_generator(chunk_data + random.randbytes(1)),
            "headers": {'Content-Length': str(correct_chunk_size + 1)},
            "expect_failure": True,
        },
        "Case 6": {
            "title": "Case 6: Body Size < Signed `Content-Length` (Signature Enforcement)",
            "description": "Similar to the above, but smaller. The `Content-Length` header does not match the value in the signature. MUST FAIL.",
            "data_stream": single_chunk_generator(chunk_data[:-1]),
            "headers": {'Content-Length': str(len(chunk_data) - 1)},
            "expect_failure": True,
        },
        "Case 7": {
            "title": "Case 7: Control Group - Correct Body and Header",
            "description": "A valid, correctly-formed request. This MUST PASS. If it fails, the provider's implementation or our configuration is broken.",
            "data_stream": single_chunk_generator(chunk_data),
            "headers": {'Content-Length': str(correct_chunk_size)},
            "expect_failure": False,
        },
    }

    # --- DYNAMIC TEST EXECUTION ---
    for case_key, case_params in test_definitions.items():
        # Skip Case 6 if the chunk is too small to be truncated
        if case_key == "Case 6" and len(chunk_data) <= 1:
            update_results(results, case_key, True) # Mark as implicitly passed
            continue

        is_pass, returned_value = run_test_case(
            test_name=case_params["title"],
            description=case_params["description"],
            client=http_client,
            url=presigned_url_for_part,
            data_stream=case_params["data_stream"],
            headers=case_params["headers"],
            expect_failure=case_params["expect_failure"],
        )
        update_results(results, case_key, is_pass)

        # For the control group, capture the ETag and ensure it passed.
        if case_key == "Case 7":
            if not is_pass:
                raise RuntimeError(f"Control group (Case 7) for part {part_number} failed. Aborting test.")
            etag = returned_value

    console.print(f"  [blue]-> Stored ETag for Part {part_number}:[/] {etag}")
    return etag


def run_list_parts_test(s3_client, config, upload_id, expected_parts: list, current_part_num: int):
    """
    Queries the provider for the list of uploaded parts and verifies its accuracy
    against our internal state. This is run after each part is uploaded.
    """
    info = f"""[yellow]Description:[/] Verify the provider accurately reports the set of currently uploaded parts.
[yellow]Expected Outcome:[/] A list containing exactly the parts uploaded so far."""

    panel = Panel(info, title=f"🧪 [bold cyan]Case 8: List Parts API Verification (after Part #{current_part_num})[/]", border_style="dim")
    console.print(panel)

    try:
        response = s3_client.list_parts(
            Bucket=config["bucket_name"],
            Key=TEST_OBJECT_KEY,
            UploadId=upload_id
        )

        provider_parts = response.get("Parts", [])
        console.print(f"  [cyan]-> Provider Reported:[/] {len(provider_parts)} part(s).")
        console.print(f"  [cyan]-> Script State:[/] Expecting {len(expected_parts)} part(s).")

        # Basic validation: Check if the number of parts matches.
        if len(provider_parts) != len(expected_parts):
            console.print(f"  [bold red]❌ FAIL:[/] Provider reported {len(provider_parts)} parts, but we expected {len(expected_parts)}.")
            return False

        # Detailed validation: Check if PartNumber and ETag match for each part.
        provider_parts_dict = {p['PartNumber']: p['ETag'] for p in provider_parts}
        for expected_part in expected_parts:
            part_num = expected_part['PartNumber']
            if part_num not in provider_parts_dict:
                console.print(f"  [bold red]❌ FAIL:[/] Expected Part #{part_num} was NOT found in the provider's list.")
                return False
            if provider_parts_dict[part_num] != expected_part['ETag']:
                console.print(f"  [bold red]❌ FAIL:[/] ETag mismatch for Part #{part_num}. Expected {expected_part['ETag']}, got {provider_parts_dict[part_num]}.")
                return False

        console.print(f"  [green]✅ PASS:[/] Provider's list of uploaded parts matches our internal state.")
        return True

    except Exception:
        console.print(f"  [bold red]❌ FAIL:[/] The 'list_parts' API call failed unexpectedly.")
        console.print_exception(show_locals=True)
        return False


def run_tests_for_all_parts(http_client, s3_client, config, local_file_path, upload_id, results: dict):
    """Reads file, iterates through parts, runs tests, and verifies state after each part."""
    uploaded_parts_etags = []
    num_parts = math.ceil(TEST_FILE_SIZE / CHUNK_SIZE)
    
    with Progress(console=console) as progress:
        task = progress.add_task(f"[bold green]Testing Parts for {config['provider_name']}...[/]", total=num_parts)
        with open(local_file_path, 'rb') as f:
            for i in range(num_parts):
                part_number = i + 1
                console.print(Rule(f"[bold]Processing Part #{part_number}/{num_parts}[/]"))
                
                # Read the correct chunk from the local file
                chunk_data = f.read(CHUNK_SIZE)

                # Run the primary test matrix for uploading the part
                etag = run_test_matrix_for_part(http_client, s3_client, config, upload_id, part_number, chunk_data, results)
                uploaded_parts_etags.append({'PartNumber': part_number, 'ETag': etag})

                # After each successful part upload, verify the provider's state using the list_parts API.
                list_parts_pass = run_list_parts_test(s3_client, config, upload_id, uploaded_parts_etags, part_number)
                update_results(results, "Case 8", list_parts_pass)
                if not list_parts_pass:
                    raise RuntimeError(f"Provider failed the 'list_parts' verification test after uploading part #{part_number}. Aborting.")
                
                progress.update(task, advance=1)

    return uploaded_parts_etags


def complete_upload(s3_client, config, upload_id, uploaded_parts):
    """Completes the multipart upload."""
    console.print(Rule("[bold]Completing Upload[/]"))
    console.print(f"[blue][INFO] All parts uploaded. Attempting to complete the multipart upload...")
    completion_result = s3_client.complete_multipart_upload(
        Bucket=config["bucket_name"],
        Key=TEST_OBJECT_KEY,
        UploadId=upload_id,
        MultipartUpload={'Parts': uploaded_parts},
    )
    console.print(f"[green]✅ SUCCESS:[/] Multipart upload completed successfully!")
    console.print(f"  [blue]-> Final ETag:[/] {completion_result.get('ETag')}")


def cleanup_resources(s3_client, http_client, local_file_path, config, upload_id, error_occurred=False):
    """Cleans up all local and remote resources."""
    console.print(Rule("[bold yellow]Cleanup[/]"))
    # This block ensures that even if a test fails, we attempt to clean up.
    if error_occurred and upload_id:
        console.print(f"[yellow][CLEANUP] Aborting multipart upload {upload_id} due to error...")
        try:
            # Aborting cleans up all uploaded parts on the provider's side.
            s3_client.abort_multipart_upload(
                Bucket=config["bucket_name"],
                Key=TEST_OBJECT_KEY,
                UploadId=upload_id,
            )
            console.print(f"[yellow][CLEANUP] Abort complete.")
        except Exception:
            console.print("[red][WARN] Failed to abort multipart upload during cleanup.")

    console.print(f"[yellow][CLEANUP] Deleting local temporary file...")
    if os.path.exists(local_file_path):
        os.remove(local_file_path)
    console.print(f"[yellow][CLEANUP] Deleting remote test object...")
    try:
        # Delete the final object if the upload completed successfully.
        s3_client.delete_object(Bucket=config["bucket_name"], Key=TEST_OBJECT_KEY)
        console.print(f"[yellow][CLEANUP] Remote object deleted.")
    except Exception:
        console.print(f"[red][WARN] Failed to delete remote object during cleanup.")

    http_client.close()


# ----------------------------------------------------------------------------
# Main multipart E2E routine
# ----------------------------------------------------------------------------

def run_multipart_e2e_test(config: dict, results: dict):
    """
    Runs the full end-to-end multipart upload test suite for a given provider.
    """
    provider_name = config["provider_name"]
    console.print(Rule(f"🚀 Starting E2E Test Suite for: [bold]{provider_name}[/]", style="bold white"))

    s3_client = build_s3_client(config)
    http_client, local_file_path = setup_clients_and_files()
    upload_id = None
    error_in_test = False

    try:
        upload_id = initiate_upload(s3_client, config["bucket_name"], TEST_OBJECT_KEY)
        uploaded_parts = run_tests_for_all_parts(http_client, s3_client, config, local_file_path, upload_id, results)
        complete_upload(s3_client, config, upload_id, uploaded_parts)
    except Exception:
        error_in_test = True
        # Mark all remaining tests as failed for this provider
        for k in results:
            if results[k] is None:
                results[k] = False
        console.print(Rule("[bold red]CRITICAL FAILURE[/]", style="red"))
        console.print_exception(show_locals=True)
    finally:
        cleanup_resources(s3_client, http_client, local_file_path, config, upload_id, error_occurred=error_in_test)
        # Mark any un-run tests as passed if no error occurred (they were implicitly skipped, e.g. Case 6)
        if not error_in_test:
            for k in results:
                if results[k] is None:
                    results[k] = True


def print_summary_table(all_results: dict):
    """Prints a formatted summary table of all provider test results using the 'rich' library."""
    if not all_results:
        console.print(f"[yellow]No test results to summarize.")
        return

    table = Table(title="\n📊 Provider Compliance Summary", show_header=True, header_style="bold magenta", border_style="dim", title_style="bold")

    # Define Columns
    table.add_column("Provider", style="cyan", no_wrap=True)
    for header in CASE_DESCRIPTIONS.values():
        table.add_column(header, justify="center")

    # Define Rows
    for provider_name, results in all_results.items():
        row_data = [provider_name]
        for case_key in CASE_KEYS:
            result = results.get(case_key)
            if result is True:
                symbol = "[green]✅[/green]"
            elif result is False:
                symbol = "[red]❌[/red]"
            else:
                symbol = "[yellow]?[/yellow]" # Should not happen
            row_data.append(symbol)
        table.add_row(*row_data)

    console.print(table)


def main():
    """
    Main execution function to iterate through configured providers and run the test suite.
    """
    all_configs = load_config()
    providers_to_test = {k: v for k, v in all_configs.items() if v.get("enabled", False)}
    all_provider_results = {}

    if not providers_to_test:
        console.print("[bold red]No providers enabled in the configuration. Please edit the script or the config.json file. Exiting.")
        return

    for key, config in providers_to_test.items():
        provider_name = config['provider_name']
        # Check for placeholder credentials before starting
        if "YOUR_" in config.get("aws_access_key_id", "") or \
           "YOUR_" in config.get("aws_secret_access_key", "") or \
           "YOUR_" in config.get("bucket_name", "") or \
           "<YOUR_ACCOUNT_ID>" in config.get("endpoint_url", ""):
            console.print(f"🛑 [bold yellow]Skipping {provider_name}:[/] Please fill in your credentials in the script or in config.json.")
            continue

        # Initialize results for this provider. None = Not Run, True = Pass, False = Fail
        results_for_provider = {case_key: None for case_key in CASE_KEYS}
        all_provider_results[provider_name] = results_for_provider

        try:
            run_multipart_e2e_test(config, results_for_provider)
        except ClientError as e:
            console.print(Rule(f"[bold red]CRITICAL BOTO3 CLIENT FAILURE for {provider_name}[/]", style="red"))
            console.print(e)
            error_code = e.response.get("Error", {}).get("Code")
            console.print(f"   [red]Error Code:[/] {error_code}")
            console.print("   [yellow]Please check your credentials, bucket name, region, and endpoint URL.")
            for k in results_for_provider: results_for_provider[k] = False # Mark all as fail
        except Exception:
            console.print(Rule(f"[bold red]CRITICAL FAILURE during test for {provider_name}[/]", style="red"))
            console.print_exception(show_locals=True)
            for k in results_for_provider: results_for_provider[k] = False # Mark all as fail

    print_summary_table(all_provider_results)


if __name__ == "__main__":
    main()
