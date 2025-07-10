# A Guide to Secure, Resumable, Quota-Enforced Large File Uploads from the Browser to S3-Compatible Storage

 ![S3 Presigned Multipart Upload Tester](https://github.com/user-attachments/assets/dc9ca3a5-d99a-47d3-aea1-43de6384ef98)


## The Problem: The S3 Multipart Upload "Enforcement Gap"

Designing a web application to handle large file uploads (from gigabytes to terabytes) presents a series of steep architectural challenges. How do you build a system that can simultaneously:

1. **Offload Bandwidth:** Avoid proxying all data through your own application servers to keep them scalable and cost-effective.
2. **Enforce Strict Quotas:** Reliably prevent a user from uploading 10 TB of data when their plan only allows for 1 GB.
3. **Support Large Files:** Gracefully handle multi-gigabyte files directly from a web browser without crashing it.
4. **Be Resumable:** Allow users to seamlessly resume an upload after a network drop or browser crash, without starting over from scratch.
5. **Be Direct-to-Storage:** Use a "serverless" client-to-storage pattern, with no stateful proxy or gateway.
6. **Be Client-Performant:** Avoid freezing the user's browser for minutes or hours by calculating a full-file checksum before uploading.
7. **Be Provider-Compatible:** Work reliably across popular S3-compatible providers like Cloudflare R2 and Backblaze B2.

This repository presents a solution that elegantly solves all of these problems: the **"Manifested Multipart Upload"** pattern.

## The Solution: Manifested Multipart Upload with Cryptographically-Enforced Chunks

The solution is to create a cryptographically-enforced contract that the storage provider validates on our behalf for every single piece of data uploaded.

This pattern leverages the native S3 Multipart Upload (MPU) protocol but adds a crucial layer of server-side orchestration and cryptographic control.

### Provider Compatibility Matrix (July 2025)

The viability of this pattern depends entirely on the S3-compatible provider's correct implementation of the AWS Signature Version 4 (SigV4) specification, particularly its enforcement of signed headers in presigned URLs.

| Provider | `Content-Length` Enforcement in Presigned `UploadPart` | Status | Notes |
| :--- | :--- | :--- | :--- |
| **AWS S3** | ✅ Yes | **Supported** | The reference implementation. Works as expected. |
| **Cloudflare R2** | ✅ Yes | **Supported** | R2's S3 compatibility layer correctly validates signed headers. |
| **Backblaze B2** | ✅ Yes | **Supported** | B2's S3-compatible API correctly validates signed headers. |
| **Google Cloud Storage** | ✅ Yes | **Supported** | GCS in "Interoperability Mode" supports and enforces this. |

As of July 2025, all major S3-compatible providers have a mature enough SigV4 implementation to correctly enforce the cryptographically-signed `Content-Length`, making this pattern a reliable choice for multi-cloud and provider-agnostic applications.

### How It Works: A Step-by-Step Guide

1.  **Initiation & Quota Check:** The user selects a file. The browser instantly knows its total size. The client makes a single API call to your backend, declaring this size. Your backend checks if this size is within the user's quota. If not, the request is rejected immediately. **No data has been transferred.**

2.  **Manifest Generation:** If the quota check passes, your backend initiates a Multipart Upload with the storage provider (R2/B2) to get a unique `UploadId`. It then calculates the number of chunks ("parts") needed.

3.  **The Cryptographic Handcuffs:** For **every single chunk**, your backend generates a unique, short-lived presigned URL. The critical step is that the chunk's exact `Content-Length` (e.g., `10485760` bytes) is included in the data that is cryptographically signed using your secret key. The resulting URL contains a signature that is only valid for a `PUT` request of that exact size.

4.  **Client Upload:** Your backend sends this full list of URLs (the "manifest") to the client. The browser then reads the file chunk by chunk and performs a simple `PUT` request for each chunk using its designated URL.

5.  **Provider Enforcement (The Critical Step):** The storage provider receives the `PUT` request. It performs a two-factor check based on the cryptographically signed contract in the URL:
    *   **Header Check:** Does the `Content-Length` header on the incoming request **exactly match** the size that was signed into the URL?
    *   **Body Check:** Does the actual size of the request body (the binary data) **exactly match** the `Content-Length` header?

    If *both* of these checks pass, the chunk is accepted. If there is **any mismatch** in either check, the signature is invalid. The provider **immediately rejects the request with a `403 SignatureDoesNotMatch` error.** The malicious or malformed data never touches persistent storage.

This pattern makes it cryptographically impossible for a user to upload more data than was pre-authorized in the manifest, satisfying all our initial requirements.

### Key Benefits of This Approach
*   **Hard Quota Enforcement:** Size limits are enforced by the storage provider at the network edge, not by your application.
*   **No Pre-Upload Hashing:** The user experience is fast and seamless. The upload can begin instantly without freezing the browser to calculate a full-file checksum.
*   **Resilience & Resumability:** The multipart nature means interrupted uploads can be resumed from the exact point of failure.
*   **Performance:** Chunks can be uploaded in parallel, saturating the user's connection and maximizing throughput.
*   **Direct-to-Storage:** No proxy server is needed; the architecture remains scalable and cost-effective.

## Implementation Pseudo-Algorithms

Here are high-level algorithms outlining the logic on both the server and client side.

### Server-Side Logic

```
// Endpoint: POST /uploads/initiate
function initiateUpload(request):
  // 1. Authenticate and authorize user
  user = authenticateUser(request.token)
  
  // 2. Validate input
  declaredSize = request.body.fileSize
  fileName = request.body.fileName
  
  // 3. Enforce Quota
  if (declaredSize > user.remainingQuota):
    return HTTP 413 (Payload Too Large)
  
  // 4. Reserve space to prevent race conditions
  reserveStorageQuota(user.organizationId, declaredSize)
  
  // 5. Initiate MPU with storage provider
  uploadId = s3_client.createMultipartUpload(bucket, fileName)
  
  // 6. Create a persistent lease/session record
  lease = database.createUploadLease(
    userId=user.id,
    uploadId=uploadId,
    declaredSize=declaredSize,
    status="Manifested"
  )
  
  // 7. Calculate parts and generate the manifest
  parts = calculateParts(declaredSize, CHUNK_SIZE)
  manifest = []
  
  for part in parts:
    // This is the critical step: sign the Content-Length
    presignedUrl = s3_client.generatePresignedUrl(
      'upload_part',
      Params={
        'Bucket': bucket,
        'Key': fileName,
        'UploadId': uploadId,
        'PartNumber': part.number,
        'ContentLength': part.size // Signed into the URL signature
      }
    )
    
    // Persist the manifest for resumability
    database.createManifestPart(
      leaseId=lease.id,
      partNumber=part.number,
      url=presignedUrl
    )
    
    manifest.append({ partNumber: part.number, url: presignedUrl })
    
  return HTTP 201 (Created) with { uploadId: uploadId, manifest: manifest }

// Endpoint: POST /uploads/{uploadId}/complete
function completeUpload(request):
  // 1. Authenticate and authorize user for this specific upload
  user = authenticateUser(request.token)
  lease = database.findUploadLease(request.params.uploadId)
  authorize(user, lease) // Ensure user owns this lease
  
  // 2. Get the list of uploaded part ETags from the client
  clientParts = request.body.parts // e.g., [{ PartNumber: 1, ETag: "..." }]
  
  // 3. Instruct storage provider to assemble the final file
  s3_client.completeMultipartUpload(
    Bucket=bucket,
    Key=lease.fileName,
    UploadId=lease.uploadId,
    MultipartUpload={'Parts': clientParts}
  )
  
  // 4. Finalize the transaction in your database
  database.updateLeaseStatus(lease.id, "Committed")
  releaseStorageQuotaReservation(user.organizationId, lease.declaredSize)
  
  return HTTP 200 (OK)
```

### Client-Side Logic (JavaScript)

```javascript
// Function triggered when user selects a file
async function handleFileSelect(file):
  // 1. Initiate the upload with our backend
  const response = await api.post('/uploads/initiate', {
    fileName: file.name,
    fileSize: file.size
  });
  
  const { uploadId, manifest } = response.data;
  const uploadedParts = [];
  
  // 2. Upload parts in parallel
  const uploadPromises = manifest.map(async (part) => {
    // Slice the file to get the specific chunk
    const chunk = file.slice(part.offset, part.offset + part.size);
    
    // Upload the chunk to the provider using the presigned URL
    const uploadResponse = await fetch(part.url, {
      method: 'PUT',
      body: chunk
    });
    
    if (!uploadResponse.ok) {
      throw new Error(`Upload failed for part ${part.partNumber}`);
    }
    
    // Store the ETag returned by the provider for the finalization step
    const eTag = uploadResponse.headers.get('ETag');
    uploadedParts.push({ PartNumber: part.partNumber, ETag: eTag });
  });
  
  await Promise.all(uploadPromises);
  
  // 3. Finalize the upload
  await api.post(`/uploads/${uploadId}/complete`, {
    parts: uploadedParts
  });
  
  console.log('Upload complete!');
```

## Verifying Your Provider: The Enforcement Tester Script

Does your S3-compatible provider *actually* enforce the signed `Content-Length` as expected? **Don't trust, verify.**

This repository includes a Python script, `s3_multipart_enforcement_tester.py`, designed to perform end-to-end tests against any S3-compatible endpoint.

### Features
-   **Provider Agnostic:** Comes pre-configured for Cloudflare R2 and Backblaze B2, and can be easily extended.
-   **Comprehensive Test Matrix:** For each chunk of a multipart upload, it runs a suite of tests to verify:
    -   ✅ **Correct uploads succeed.** (Control Group)
    -   ❌ **Oversized bodies are rejected.**
    -   ❌ **Undersized bodies are rejected.**
    -   ❌ **Requests with a `Content-Length` header that doesn't match the signed value are rejected.**
-   **Clear Pass/Fail Reporting:** Provides detailed console output, clearly indicating whether your provider is behaving securely.

### How to Use

1.  **Install Dependencies:**
    ```bash
    pip install boto3 httpx tqdm
    ```

2.  **Configure Your Providers:**
    Configuration can be done in one of two ways. The `config.json` method is recommended for keeping credentials out of version control.
    *   **Method A (Recommended): Create `config.json`**
        -   Create a file named `config.json` in the same directory.
        -   Copy the structure from the `DEFAULT_PROVIDERS` dictionary in the script.
        -   Set `"enabled": true` and fill in your `endpoint_url`, credentials, and `bucket_name`.
    *   **Method B: Edit the Script Directly**
        -   Modify the `DEFAULT_PROVIDERS` dictionary within the Python script.

    **Example `config.json` for Cloudflare R2:**
    ```json
    {
      "r2": {
        "provider_name": "Cloudflare R2",
        "enabled": true,
        "endpoint_url": "https://<YOUR_ACCOUNT_ID>.r2.cloudflarestorage.com",
        "aws_access_key_id": "YOUR_R2_ACCESS_KEY",
        "aws_secret_access_key": "YOUR_R2_SECRET_KEY",
        "region_name": "auto",
        "bucket_name": "my-test-bucket",
        "addressing_style": "path"
      }
    }
    ```

3.  **Run the Test:**
    ```bash
    python s3_multipart_enforcement_tester.py
    ```

The script will generate a temporary file, run the full test matrix against each enabled provider, and clean up all local and remote resources afterward.

## A Comparative Analysis of Architectural Patterns

The "Manifested Multipart" pattern is our recommended solution for meeting all seven of the initial requirements. It's helpful to understand why other common architectures fall short.

| Pattern | Enforces Quota? | Resumable? | Direct-to-Storage? | Works on popular S3 providers? | Key Weakness |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Presigned POST Policy** | ✅ Yes | ❌ No | ✅ Yes | ❌ **No** | Not resumable; Not supported by B2. |
| **2. tus.io Protocol** | ✅ Yes | ✅ Yes | ❌ No | ✅ Yes | Requires a stateful intermediary server (proxy). |
| **3. Streaming Gateway** | ✅ Yes | ❌ No | ❌ No | ✅ Yes | Major performance/scalability bottleneck. |
| **4. Manifested Multipart (This Repo)**| ✅ Yes | ✅ Yes | ✅ Yes | ✅ Yes | **Meets all requirements.** |

---

#### **Pattern 1: Presigned POST with `content-length-range`**
*   **How it Works:** The backend signs a policy document that S3 enforces, including a maximum file size.
*   **Why it Fails:** While secure, it's **not resumable**, making it unsuitable for large file uploads. Critically, it is **not supported by Cloudflare R2, Backblaze B2 and other providers S3 API**, making it a non-starter for multi-provider compatibility.

#### **Pattern 2: The tus.io Protocol**
*   **How it Works:** A specialized, open-source protocol for resumable uploads.
*   **Why it Fails:** It is an excellent protocol, but it **requires a stateful intermediary server** (`tusd`) to manage the connection. This violates the "Direct-to-Storage" requirement and adds an extra service to deploy, manage, and scale.

#### **Pattern 3: Streaming Gateway Proxy**
*   **How it Works:** The client uploads directly to your backend server, which streams the data to S3.
*   **Why it Fails:** This is a major performance and scalability anti-pattern. It puts your application server in the data path, negating the benefits of direct-to-storage uploads and creating a bottleneck that violates the "Offload Bandwidth" requirement.

#### **Pattern 4: Manifested Multipart (Our Recommended Solution)**
*   **How it Works:** As described above, by pre-generating a list of cryptographically size-constrained part URLs.
*   **Why it Succeeds:** It is the only pattern that achieves the security of a gateway and the resumability of `tus` **without requiring an intermediary server.** It leverages the native S3 protocol directly, satisfying all seven of the initial requirements.
