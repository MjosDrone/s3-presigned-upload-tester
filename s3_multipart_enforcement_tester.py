#!/usr/bin/env python3
#
# Filename: s3_multipart_enforcement_tester.py
#
# ==============================================================================
# S3 Multipart Upload Content-Length Enforcement Tester
# ==============================================================================
#
# PURPOSE:
# This script performs an end-to-end test to verify that an S3-compatible
# storage provider correctly and cryptographically enforces the 'Content-Length'
# of chunks uploaded via a presigned multipart upload URL.
#
# It answers the question: "If I tell my provider I'm uploading a 5 MiB
# chunk, can a malicious user use that URL to upload a 6 MiB chunk and
# abuse my storage quota?" For a correctly configured provider, the answer
# must be NO.
#
#
# HOW TO USE:
#
# 1. Install Dependencies:
#    pip install boto3 httpx tqdm
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
#    - The script will run a matrix of tests for each part of a sample file.
#    - A `✅ PASS` means the provider behaved as expected (either rejecting a
#      bad request or accepting a good one).
#    - A `❌ FAIL` indicates a potential security vulnerability where the
#      provider did not correctly enforce the signed content length.
#
# ==============================================================================
"""
Self‑contained end‑to‑end multipart‑upload size‑enforcement test for
S3-compatible storage providers like Backblaze B2 and Cloudflare R2.

"""

import boto3
import httpx
import sys
import os
import tempfile
import math
import json
import random
from tqdm import tqdm  # noqa: F401 – retained for potential future progress bars
from botocore.client import Config
from botocore.exceptions import ClientError
from urllib.parse import urlparse
from h11 import LocalProtocolError  # Import specific exception for httpx client-side errors
from copy import deepcopy

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

# --- Improved Reporting ---
class C:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    END = "\033[0m"


# ----------------------------------------------------------------------------
# Helper functions – new code kept small & specific per Coding Rules
# ----------------------------------------------------------------------------

def load_config():
    """Loads config from external file and merges it with defaults."""
    config = deepcopy(DEFAULT_PROVIDERS)
    if os.path.exists(CONFIG_FILE_NAME):
        print(f"{C.BLUE}[INFO] Loading configuration from '{CONFIG_FILE_NAME}'...{C.END}")
        with open(CONFIG_FILE_NAME, 'r') as f:
            external_config = json.load(f)

        # Merge external config into the default config
        for provider_key, provider_config in external_config.items():
            if provider_key in config:
                config[provider_key].update(provider_config)
            else:
                config[provider_key] = provider_config
    else:
        print(f"{C.YELLOW}[WARN] No '{CONFIG_FILE_NAME}' found. Using default inline configuration.{C.END}")
        print(f"{C.YELLOW}[WARN] It is recommended to use an external file for credentials.{C.END}")

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
    print(f"\n  🧪 {C.BOLD}{test_name}{C.END}")
    print(f"     - {C.YELLOW}Description:{C.END} {description}")
    print(f"     - {C.YELLOW}Headers:{C.END} {headers}")
    print(f"     - {C.YELLOW}Expected Outcome:{C.END} {'FAILURE (non-200 code or client/server exception)' if expect_failure else 'SUCCESS (HTTP 200)'}")

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
            print(f"  - {C.GREEN}✅ PASS: Provider correctly ACCEPTED the valid request (HTTP {status_code}).{C.END}")
            return True, response.headers.get('ETag')
        else:
            # This is a critical failure: the provider accepted a request it should have rejected.
            print(f"  - {C.RED}❌ FAIL: Provider INCORRECTLY accepted a bad request with HTTP {status_code}. SECURITY RISK.{C.END}")
            print(f"  - Response Body: {response.text[:200]}...")
            return False, None

    except (LocalProtocolError, httpx.HTTPError) as e:
        # This block catches three types of failures, which are EXPECTED for invalid requests:
        # 1. LocalProtocolError: httpx's client-side validation caught an error (e.g., body size mismatch).
        # 2. httpx.RequestError: A network-level error occurred (e.g., connection closed by server).
        # 3. httpx.HTTPStatusError: Server responded with 4xx or 5xx (from raise_for_status).
        if expect_failure:
            print(f"  - Request failed with an expected exception: {C.YELLOW}{type(e).__name__}: {e}{C.END}")
            print(f"  - {C.GREEN}✅ PASS: The client/provider correctly REJECTED the invalid request via exception.{C.END}")
            return True, None
        else:
            # An exception during a valid request (control group) is a hard failure.
            print(f"  - {C.RED}❌ FAIL: A valid request failed unexpectedly with exception: {type(e).__name__}: {e}{C.END}")
            return False, None
    finally:
        print("-" * 25)


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
    print(f"{C.BLUE}[INFO] Generating a temporary {TEST_FILE_SIZE / (1024*1024):.0f} MiB test file at: {local_file_path}{C.END}")
    with os.fdopen(fd, 'wb') as f:
        f.write(os.urandom(TEST_FILE_SIZE))
    print(f"{C.BLUE}[INFO] Test file generated.{C.END}")
    return http_client, local_file_path


def initiate_upload(s3_client, bucket, key):
    """Initiates a multipart upload and returns the UploadId."""
    print(f"{C.BLUE}[INFO] Initiating multipart upload for '{key}'...{C.END}")
    response = s3_client.create_multipart_upload(Bucket=bucket, Key=key)
    upload_id = response['UploadId']
    print(f"{C.BLUE}[INFO] Multipart upload initiated. UploadId: {upload_id}{C.END}")
    return upload_id


def run_test_matrix_for_part(http_client, s3_client, config, upload_id, part_number, chunk_data):
    """Runs all enforcement tests for a single part and returns its ETag on success."""
    correct_chunk_size = len(chunk_data)

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

    # --- TEST MATRIX FOR THIS PART ---
    # This matrix tests various ways a client could misrepresent the size of the data.
    # A secure provider must reject all but the control group.

    run_test_case(
        "Case 1: Header `Content-Length` > Actual Body Size (Client Error)",
        "Tests client-side errors where the header claims more data than is sent. The HTTP client library itself should ideally catch this.",
        client=http_client, url=presigned_url_for_part,
        data_stream=single_chunk_generator(chunk_data),
        headers={'Content-Length': str(correct_chunk_size + 1)},
        expect_failure=True,
    )

    run_test_case(
        "Case 2: Header `Content-Length` < Actual Body Size (Client Error)",
        "Tests client-side errors where the header claims less data than is sent. The HTTP client library should prevent this.",
        client=http_client, url=presigned_url_for_part,
        data_stream=single_chunk_generator(chunk_data),
        headers={'Content-Length': str(correct_chunk_size - 1)},
        expect_failure=True,
    )

    run_test_case(
        "Case 3: Body Size < Header `Content-Length` (Server-Side Enforcement)",
        "The client sends a correct header but prematurely ends the data stream. The server must detect the size mismatch and reject the request.",
        client=http_client, url=presigned_url_for_part,
        data_stream=truncated_chunk_generator(chunk_data),
        headers={'Content-Length': str(correct_chunk_size)},
        expect_failure=True,
    )

    run_test_case(
        "Case 4: Body Size > Header `Content-Length` (Server-Side Enforcement)",
        "The client sends a correct header but tries to stream extra data. The server must stop reading after `Content-Length` bytes and reject the request.",
        client=http_client, url=presigned_url_for_part,
        data_stream=extended_chunk_generator(chunk_data),
        headers={'Content-Length': str(correct_chunk_size)},
        expect_failure=True,
    )

    larger_data = chunk_data + random.randbytes(1)
    run_test_case(
        "Case 5: Body Size > Signed `Content-Length` (Signature Enforcement)",
        "The most critical test. The client sends a body and a matching header, but their size is LARGER than what was signed in the URL. MUST FAIL.",
        client=http_client, url=presigned_url_for_part,
        data_stream=single_chunk_generator(larger_data),
        headers={'Content-Length': str(len(larger_data))},
        expect_failure=True,
    )

    if len(chunk_data) > 1:
        smaller_data = chunk_data[:-1]
        run_test_case(
            "Case 6: Body Size < Signed `Content-Length` (Signature Enforcement)",
            "Similar to the above, but smaller. The `Content-Length` header does not match the value in the signature. MUST FAIL.",
            client=http_client, url=presigned_url_for_part,
            data_stream=single_chunk_generator(smaller_data),
            headers={'Content-Length': str(len(smaller_data))},
            expect_failure=True,
        )

    # The control group validates that a legitimate, correctly formed request is accepted.
    control_pass, etag = run_test_case(
        "Case 7: Control Group - Correct Body and Header",
        "A valid, correctly-formed request. This MUST PASS. If it fails, the provider's implementation or our configuration is broken.",
        client=http_client, url=presigned_url_for_part,
        data_stream=single_chunk_generator(chunk_data),
        headers={'Content-Length': str(correct_chunk_size)},
        expect_failure=False,
    )

    if not control_pass:
        raise RuntimeError(f"Control group for part {part_number} failed. This indicates a fundamental problem with the provider or configuration. Aborting test.")

    print(f"  {C.BLUE}[INFO] Stored ETag for Part {part_number}: {etag}{C.END}")
    return etag


def run_tests_for_all_parts(http_client, s3_client, config, local_file_path, upload_id):
    """Reads file, iterates through parts, and runs the test matrix for each."""
    uploaded_parts_etags = []
    num_parts = math.ceil(TEST_FILE_SIZE / CHUNK_SIZE)
    with open(local_file_path, 'rb') as f:
        for i in range(num_parts):
            part_number = i + 1
            print("\n" + "="*40)
            print(f"{C.BOLD}Processing Part #{part_number}/{num_parts}{C.END}")
            print("="*40)

            # Read the correct chunk from the local file
            chunk_data = f.read(CHUNK_SIZE)

            etag = run_test_matrix_for_part(http_client, s3_client, config, upload_id, part_number, chunk_data)
            uploaded_parts_etags.append({'PartNumber': part_number, 'ETag': etag})
    return uploaded_parts_etags


def complete_upload(s3_client, config, upload_id, uploaded_parts):
    """Completes the multipart upload."""
    print("\n" + "="*60)
    print(f"{C.BLUE}[INFO] All parts uploaded. Attempting to complete the multipart upload...{C.END}")
    completion_result = s3_client.complete_multipart_upload(
        Bucket=config["bucket_name"],
        Key=TEST_OBJECT_KEY,
        UploadId=upload_id,
        MultipartUpload={'Parts': uploaded_parts},
    )
    print(f"{C.GREEN}✅ SUCCESS: Multipart upload completed successfully!{C.END}")
    print(f"Final ETag: {completion_result.get('ETag')}")


def cleanup_resources(s3_client, http_client, local_file_path, config, upload_id, error_occurred=False):
    """Cleans up all local and remote resources."""
    # This block ensures that even if a test fails, we attempt to clean up.
    if error_occurred and upload_id:
        print(f"{C.YELLOW}[CLEANUP] Aborting multipart upload {upload_id} due to error...{C.END}")
        try:
            # Aborting cleans up all uploaded parts on the provider's side.
            s3_client.abort_multipart_upload(
                Bucket=config["bucket_name"],
                Key=TEST_OBJECT_KEY,
                UploadId=upload_id,
            )
            print(f"{C.YELLOW}[CLEANUP] Abort complete.{C.END}")
        except Exception as e:
            print(f"[WARN] Failed to abort multipart upload during cleanup: {e}", file=sys.stderr)

    print(f"\n{C.YELLOW}[CLEANUP] Deleting local temporary file...{C.END}")
    if os.path.exists(local_file_path):
        os.remove(local_file_path)
    print(f"{C.YELLOW}[CLEANUP] Deleting remote test object...{C.END}")
    try:
        # Delete the final object if the upload completed successfully.
        s3_client.delete_object(Bucket=config["bucket_name"], Key=TEST_OBJECT_KEY)
        print(f"{C.YELLOW}[CLEANUP] Remote object deleted.{C.END}")
    except Exception as e:
        print(f"[WARN] Failed to delete remote object during cleanup: {e}", file=sys.stderr)

    http_client.close()


# ----------------------------------------------------------------------------
# Main multipart E2E routine
# ----------------------------------------------------------------------------

def run_multipart_e2e_test(config: dict):
    """
    Runs the full end-to-end multipart upload test suite for a given provider.
    """
    provider_name = config["provider_name"]
    print("=" * 60)
    print(f"🚀 {C.BOLD}Starting E2E Multipart Test Suite for: {provider_name}{C.END}")
    print("=" * 60)

    s3_client = build_s3_client(config)
    http_client, local_file_path = setup_clients_and_files()
    upload_id = None
    error_in_test = False

    try:
        upload_id = initiate_upload(s3_client, config["bucket_name"], TEST_OBJECT_KEY)
        uploaded_parts = run_tests_for_all_parts(http_client, s3_client, config, local_file_path, upload_id)
        complete_upload(s3_client, config, upload_id, uploaded_parts)
    except Exception as e:
        error_in_test = True
        print(f"\n{C.RED}❌ An error occurred during the test: {e} {type(e)} {C.END}", file=sys.stderr)
    finally:
        cleanup_resources(s3_client, http_client, local_file_path, config, upload_id, error_occurred=error_in_test)


def main():
    """
    Main execution function to iterate through configured providers and run the test suite.
    """
    all_configs = load_config()
    providers_to_test = {k: v for k, v in all_configs.items() if v.get("enabled", False)}

    if not providers_to_test:
        print("No providers enabled in the configuration. Please edit the script or the config.json file. Exiting.", file=sys.stderr)
        return

    for key, config in providers_to_test.items():
        # Check for placeholder credentials before starting
        if "YOUR_" in config.get("aws_access_key_id", "") or \
           "YOUR_" in config.get("aws_secret_access_key", "") or \
           "YOUR_" in config.get("bucket_name", "") or \
           "<YOUR_ACCOUNT_ID>" in config.get("endpoint_url", ""):
            print(f"🛑 Skipping {config['provider_name']}: Please fill in your credentials in the script or in config.json.", file=sys.stderr)
            continue

        try:
            run_multipart_e2e_test(config)
        except ClientError as e:
            print(f"\n{C.RED}CRITICAL BOTO3 CLIENT FAILURE for {config['provider_name']}: {e}{C.END}", file=sys.stderr)
            error_code = e.response.get("Error", {}).get("Code")
            print(f"   Error Code: {error_code}", file=sys.stderr)
            print("   Please check your credentials, bucket name, region, and endpoint URL.", file=sys.stderr)
        except Exception as e:
            print(f"\n{C.RED}CRITICAL FAILURE during test for {config['provider_name']}: {e}{C.END}", file=sys.stderr)


if __name__ == "__main__":
    main()
