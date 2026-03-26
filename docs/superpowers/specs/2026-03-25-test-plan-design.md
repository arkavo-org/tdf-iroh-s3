# tdf-iroh-s3 Manual QA Test Plan

## Overview

A manual QA test plan for verifying the tdf-iroh-s3 system deployed on a real EC2 instance with real S3. Covers service health, TDF ingest/retrieval, rejection cases, idempotency, configuration variants, and service resilience.

## Prerequisites

### 1. Test CLI Binary

Build a test CLI binary (`tdf-iroh-s3-test`) from this repo as a separate binary target. It uses the existing dependencies (iroh, iroh-blobs, opentdf) to act as an Iroh peer client.

**Capabilities:**
- Create TDFs with configurable attributes using `opentdf-rs` (`PolicyBuilder`, `Tdf::encrypt`)
- Connect to a running tdf-iroh-s3 node by its Endpoint ID
- Push blobs to the node over Iroh's QUIC protocol
- Fetch blobs by BLAKE3 hash from the node
- Send invalid payloads (garbage bytes, TDF with wrong attributes)
- Print BLAKE3 hash of sent blobs for verification

**Commands:**
```
tdf-iroh-s3-test push --node <ENDPOINT_ID> --attribute <FQN> --data <FILE_OR_STRING>
tdf-iroh-s3-test push-raw --node <ENDPOINT_ID> --data <FILE>   # send raw bytes, no TDF wrapping
tdf-iroh-s3-test fetch --node <ENDPOINT_ID> --hash <BLAKE3_HEX>
tdf-iroh-s3-test create-tdf --attribute <FQN> --output <FILE>  # create TDF file locally
```

### 2. AWS Resources

| Resource | Description |
|----------|-------------|
| AMI | Built from `packer/ami.pkr.hcl` |
| EC2 instance | Launched from AMI with user-data config |
| S3 bucket | Empty bucket for test (e.g., `test-tdf-iroh-s3`) |
| IAM role | Instance profile with S3 permissions on the test bucket |
| Security group | UDP inbound on port 11204 (QUIC) |

### 3. Test Configuration

User-data for the test EC2 instance:
```toml
[iroh]
bind_port = 11204

[s3]
bucket = "test-tdf-iroh-s3"
region = "us-east-1"

[validation]
required_attributes = [
    "https://example.com/attr/storage/value/permanent"
]

[validation.assertion]
enabled = false
trusted_public_keys = []
```

### 4. Tools

- AWS CLI (`aws s3`, `aws s3api`)
- SSH access to the EC2 instance
- The test CLI binary (built locally, run from a machine that can reach the EC2 instance)

---

## Section 1: AMI Launch & Service Health

**Goal:** Verify the instance boots, the service starts, and configuration is loaded from user-data.

### Test 1.1: Instance Boots Successfully

**Steps:**
1. Launch EC2 instance from the built AMI with the test config as user-data
2. Wait for instance to reach "running" state
3. SSH into the instance

**Expected:** Instance is reachable via SSH

### Test 1.2: Service Is Running

**Steps:**
1. SSH into instance
2. Run: `sudo systemctl status tdf-iroh-s3`

**Expected:**
- Service is `active (running)`
- No errors in status output
- `ExecStartPre` (bootstrap) completed successfully

### Test 1.3: Config Was Loaded from User-Data

**Steps:**
1. SSH into instance
2. Run: `cat /etc/tdf-iroh-s3/config.toml`

**Expected:**
- File exists and contains the TOML config from user-data
- Owned by `tdf-iroh-s3:tdf-iroh-s3`, permissions `640`

### Test 1.4: Service Logs Show Successful Startup

**Steps:**
1. SSH into instance
2. Run: `sudo journalctl -u tdf-iroh-s3 --no-pager -n 50`

**Expected:** Logs show:
- "Config loaded from ..."
- "S3: test-tdf-iroh-s3:us-east-1"
- "Required attributes: [...]"
- "Iroh endpoint bound on port 11204"
- "Iroh endpoint online"
- "Node ID: ..." (record this Endpoint ID for subsequent tests)

### Test 1.5: Node Identity Key Was Generated

**Steps:**
1. SSH into instance
2. Run: `ls -la /var/lib/tdf-iroh-s3/secret.key`

**Expected:** File exists, owned by `tdf-iroh-s3`, non-empty

### Test 1.6: Service User Is Non-Root

**Steps:**
1. SSH into instance
2. Run: `ps aux | grep tdf-iroh-s3`

**Expected:** Process running as user `tdf-iroh-s3`, not `root`

---

## Section 2: Valid TDF Ingest

**Goal:** Push a valid TDF with the required attribute and verify it is stored in S3.

### Test 2.1: Push Valid TDF

**Steps:**
1. Note the Endpoint ID from Test 1.4 logs
2. From the test machine, run:
   ```
   tdf-iroh-s3-test push \
     --node <ENDPOINT_ID> \
     --attribute "https://example.com/attr/storage/value/permanent" \
     --data "Hello, TDF world"
   ```
3. Note the BLAKE3 hash printed by the test CLI

**Expected:**
- Push completes without error
- CLI prints the BLAKE3 hash (64 hex characters)

### Test 2.2: Verify Blob in S3

**Steps:**
1. Using the hash from Test 2.1, run:
   ```
   aws s3api head-object \
     --bucket test-tdf-iroh-s3 \
     --key "blobs/<BLAKE3_HASH>"
   ```

**Expected:**
- Object exists
- Content length > 0 (TDF is a ZIP, so it's larger than the raw payload)

### Test 2.3: Verify Service Logs Show Ingest

**Steps:**
1. SSH into instance
2. Run: `sudo journalctl -u tdf-iroh-s3 --no-pager -n 20`

**Expected:** Log line showing "Blob ingested and stored to S3" with the matching hash

---

## Section 3: TDF Retrieval

**Goal:** Fetch a previously stored blob back from the node and verify the content matches.

### Test 3.1: Fetch Blob by Hash

**Steps:**
1. Using the hash from Test 2.1, run:
   ```
   tdf-iroh-s3-test fetch \
     --node <ENDPOINT_ID> \
     --hash <BLAKE3_HASH>
   ```
2. Save the output to a file

**Expected:**
- Fetch completes without error
- Downloaded bytes are a valid TDF (ZIP with manifest.json + payload)

### Test 3.2: Verify Content Integrity

**Steps:**
1. Compute BLAKE3 hash of the downloaded file
2. Compare to the original hash from Test 2.1

**Expected:** Hashes match exactly

### Test 3.3: Fetch Non-Existent Hash

**Steps:**
1. Run:
   ```
   tdf-iroh-s3-test fetch \
     --node <ENDPOINT_ID> \
     --hash 0000000000000000000000000000000000000000000000000000000000000000
   ```

**Expected:** Fetch fails with a "not found" error — node does not serve data it doesn't have

---

## Section 4: Rejection Cases

**Goal:** Verify the node rejects invalid blobs and nothing is stored in S3.

### Test 4.1: Reject Garbage Bytes

**Steps:**
1. Create a file with random bytes: `dd if=/dev/urandom of=/tmp/garbage.bin bs=256 count=1`
2. Run:
   ```
   tdf-iroh-s3-test push-raw \
     --node <ENDPOINT_ID> \
     --data /tmp/garbage.bin
   ```
3. Compute BLAKE3 hash of the garbage file
4. Check S3: `aws s3api head-object --bucket test-tdf-iroh-s3 --key "blobs/<HASH>"`

**Expected:**
- Push is rejected with an error (TDF structure validation failed)
- S3 HEAD returns 404 — nothing stored

### Test 4.2: Reject TDF with Wrong Attribute

**Steps:**
1. Create a TDF with a non-matching attribute:
   ```
   tdf-iroh-s3-test push \
     --node <ENDPOINT_ID> \
     --attribute "https://example.com/attr/level/value/public" \
     --data "wrong attribute data"
   ```
2. Compute the BLAKE3 hash
3. Check S3

**Expected:**
- Push is rejected (attribute validation failed)
- Nothing in S3

### Test 4.3: Reject TDF with No Attributes

**Steps:**
1. Create and push a TDF with no attributes at all:
   ```
   tdf-iroh-s3-test push \
     --node <ENDPOINT_ID> \
     --attribute "" \
     --data "no attributes"
   ```
2. Check S3

**Expected:**
- Push is rejected (required attribute missing)
- Nothing in S3

### Test 4.4: Verify Service Logs Show Rejections

**Steps:**
1. SSH into instance
2. Check logs: `sudo journalctl -u tdf-iroh-s3 --no-pager -n 30`

**Expected:** Log entries showing rejection reasons for each failed push (structure validation, attribute validation)

---

## Section 5: Duplicate Handling

**Goal:** Verify that pushing the same TDF twice does not create duplicate S3 objects.

### Test 5.1: Push Same TDF Twice

**Steps:**
1. Create a TDF locally:
   ```
   tdf-iroh-s3-test create-tdf \
     --attribute "https://example.com/attr/storage/value/permanent" \
     --output /tmp/test.tdf
   ```
2. Push it to the node:
   ```
   tdf-iroh-s3-test push \
     --node <ENDPOINT_ID> \
     --attribute "https://example.com/attr/storage/value/permanent" \
     --data @/tmp/test.tdf
   ```
3. Note the BLAKE3 hash
4. Push the exact same file again
5. List S3 objects:
   ```
   aws s3api list-objects-v2 \
     --bucket test-tdf-iroh-s3 \
     --prefix "blobs/<HASH>"
   ```

**Expected:**
- Both pushes succeed (second is a no-op)
- Only one S3 object with that key exists
- Logs show "Blob already exists in S3, skipping upload" for the second push

---

## Section 6: Configuration Variants

**Goal:** Verify the same AMI works with different configurations.

### Test 6.1: No Required Attributes (Accept Any TDF)

**Steps:**
1. Launch a new instance from the same AMI with config:
   ```toml
   [iroh]
   bind_port = 11204

   [s3]
   bucket = "test-tdf-iroh-s3"
   region = "us-east-1"
   prefix = "variant-a/"

   [validation]
   required_attributes = []
   ```
2. Push a TDF with any attribute:
   ```
   tdf-iroh-s3-test push \
     --node <ENDPOINT_ID> \
     --attribute "https://example.com/attr/anything/value/whatever" \
     --data "any attribute works"
   ```
3. Check S3 under the `variant-a/` prefix:
   ```
   aws s3 ls s3://test-tdf-iroh-s3/variant-a/blobs/
   ```

**Expected:**
- Push succeeds
- Blob stored under `variant-a/blobs/<HASH>`

### Test 6.2: S3 Prefix Isolation

**Steps:**
1. Verify the `variant-a/` instance's blobs are only under `variant-a/blobs/`
2. Verify the original instance's blobs are only under `blobs/` (no prefix)

**Expected:** Each deployment's blobs are isolated by prefix

### Test 6.3: Assertion Check Enabled (Rejection)

**Steps:**
1. Launch a new instance with config:
   ```toml
   [iroh]
   bind_port = 11204

   [s3]
   bucket = "test-tdf-iroh-s3"
   region = "us-east-1"
   prefix = "variant-b/"

   [validation]
   required_attributes = []

   [validation.assertion]
   enabled = true
   trusted_public_keys = ["/etc/tdf-iroh-s3/trusted-keys/test.pem"]
   ```
2. Place a test public key at `/etc/tdf-iroh-s3/trusted-keys/test.pem` on the instance
3. Push a standard TDF (no signed assertion):
   ```
   tdf-iroh-s3-test push \
     --node <ENDPOINT_ID> \
     --attribute "https://example.com/attr/storage/value/permanent" \
     --data "needs assertion"
   ```

**Expected:**
- Push is rejected (assertion check enabled, TDF has no matching assertion)
- Nothing in S3 under `variant-b/`

---

## Section 7: Service Resilience

**Goal:** Verify the service recovers from restarts and still serves previously stored blobs.

### Test 7.1: Service Restart

**Steps:**
1. SSH into the original test instance
2. Record a BLAKE3 hash of a previously stored blob
3. Run: `sudo systemctl restart tdf-iroh-s3`
4. Wait 10 seconds
5. Run: `sudo systemctl status tdf-iroh-s3`

**Expected:** Service is `active (running)` again

### Test 7.2: Fetch After Restart

**Note:** The Endpoint ID may change after restart if the node secret key is not persisted, or remain the same if it is. Check the post-restart logs for the new Endpoint ID.

**Steps:**
1. Check logs for the post-restart Endpoint ID: `sudo journalctl -u tdf-iroh-s3 --no-pager -n 10`
2. From the test machine:
   ```
   tdf-iroh-s3-test fetch \
     --node <NEW_OR_SAME_ENDPOINT_ID> \
     --hash <PREVIOUSLY_STORED_HASH>
   ```

**Expected:**
- Fetch succeeds
- Content matches (hash verification passes)
- The node serves from S3 despite the restart (stateless — S3 is the durable store)
- If the secret key was persisted, the Endpoint ID should be the same as before restart

### Test 7.3: Push After Restart

**Steps:**
1. Push a new valid TDF after the restart
2. Verify it lands in S3

**Expected:** Node accepts and stores new blobs after restart

### Test 7.4: Service Crash Recovery

**Steps:**
1. SSH into instance
2. Kill the process: `sudo kill -9 $(pidof tdf-iroh-s3)`
3. Wait 10 seconds (systemd `Restart=on-failure` should restart it)
4. Run: `sudo systemctl status tdf-iroh-s3`

**Expected:**
- Service restarted automatically
- Status shows `active (running)`
- Logs show clean startup after crash

---

## Test Execution Checklist

| # | Test | Result | Notes |
|---|------|--------|-------|
| 1.1 | Instance boots | ☐ | |
| 1.2 | Service running | ☐ | |
| 1.3 | Config from user-data | ☐ | |
| 1.4 | Startup logs correct | ☐ | Endpoint ID: ________ |
| 1.5 | Node key generated | ☐ | |
| 1.6 | Non-root user | ☐ | |
| 2.1 | Push valid TDF | ☐ | Hash: ________ |
| 2.2 | Blob in S3 | ☐ | |
| 2.3 | Ingest log entry | ☐ | |
| 3.1 | Fetch by hash | ☐ | |
| 3.2 | Content integrity | ☐ | |
| 3.3 | Fetch non-existent | ☐ | |
| 4.1 | Reject garbage | ☐ | |
| 4.2 | Reject wrong attr | ☐ | |
| 4.3 | Reject no attrs | ☐ | |
| 4.4 | Rejection logs | ☐ | |
| 5.1 | Duplicate handling | ☐ | |
| 6.1 | No required attrs | ☐ | |
| 6.2 | S3 prefix isolation | ☐ | |
| 6.3 | Assertion enabled | ☐ | |
| 7.1 | Service restart | ☐ | |
| 7.2 | Fetch after restart | ☐ | |
| 7.3 | Push after restart | ☐ | |
| 7.4 | Crash recovery | ☐ | |

## Cleanup

After testing:
1. Terminate all EC2 instances
2. Empty and delete the test S3 bucket: `aws s3 rb s3://test-tdf-iroh-s3 --force`
3. Delete the AMI and associated snapshots
4. Remove the IAM role and instance profile
