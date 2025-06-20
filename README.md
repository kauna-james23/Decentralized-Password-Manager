# 🔐 Decentralized Password Manager – Smart Contract

A **production-ready Clarity smart contract** for secure, encrypted credential storage, with features like **multi-device synchronization**, **social recovery**, and **secure sharing**. Designed for resilience, privacy, and user control.

---

## ✨ Features

### 🧰 Vault & Device Management

* **Initialize Vault**: Create a secure vault with a hashed master key and recovery guardians.
* **Multi-Device Sync**: Add up to 10 authorized devices per user, each with its own public key and encrypted master key.
* **Device Tracking**: View and manage devices with metadata (last active, public key, etc.).

### 🔐 Credential Management

* **Secure Storage**: Store credentials encrypted end-to-end (no plaintext ever on-chain).
* **Audit-Ready**: Track metadata hash and last-modified block for version control.
* **Delete Credential**: Devices can delete credentials with proper authorization.

### 🛟 Social Recovery

* **Guardians-Based Recovery**: Assign trusted guardians to help recover lost vault access.
* **Quorum-Based Approval**: Minimum of 3 out of 10 guardian approvals required to recover vault.
* **Recovery Timeout**: Recovery requests automatically expire after 24 hours (\~144 blocks).

### 🔄 Credential Sharing

* **Encrypted Sharing**: Share credentials securely with read-only or full-access permissions.
* **Expiration Handling**: Shared credentials auto-expire after 1 week (\~1008 blocks).
* **Revocation**: Users can manually revoke access to shared credentials.

---

## 🧱 Contract Structure

### Maps & Data Structures

| Name                 | Purpose                                                           |
| -------------------- | ----------------------------------------------------------------- |
| `user-vaults`        | Stores user vault metadata (master key hash, guardian list, etc.) |
| `user-devices`       | Stores per-device encryption and activity state                   |
| `credentials`        | Encrypted user credentials                                        |
| `recovery-requests`  | Active recovery flows and guardian approvals                      |
| `shared-credentials` | Securely shared credentials with expiry and permissions           |
| `user-device-list`   | Lists device IDs for each user                                    |

### Constants

* `MAX-DEVICES-PER-USER`: `10`
* `MIN-RECOVERY-GUARDIANS`: `3`
* `RECOVERY-TIMEOUT-BLOCKS`: \~24 hours (`144`)
* `SHARE-EXPIRY-BLOCKS`: \~1 week (`1008`)

---

## 🔍 Read-Only Functions

* `get-vault-info(user)`
* `get-device-info(user, device-id)`
* `get-user-devices(user)`
* `get-recovery-status(user)`
* `get-shared-credential(from-user, to-user, share-id)`
* `is-recovery-guardian(user, potential-guardian)`

---

## 🔐 Access Control

| Function                                | Access                     |
| --------------------------------------- | -------------------------- |
| `initialize-vault`                      | Public (per user)          |
| `add-device`                            | Must be authorized device  |
| `store-credential`, `delete-credential` | Authorized device only     |
| `initiate-recovery`, `approve-recovery` | Recovery guardian only     |
| `share-credential`, `revoke-share`      | Sender’s authorized device |

---

## 💡 Example Flow

1. User A initializes a vault with a master key and 3 guardians.
2. Adds Device 1 and Device 2 to the vault.
3. Device 1 stores multiple encrypted credentials.
4. Device 2 shares a credential with User B (read-only).
5. User A loses access and triggers social recovery via guardians.
6. After 3 approvals, User A’s vault is reset with a new key.

---

## 🛠 Deployment & Usage

> This is a smart contract written in [Clarity](https://docs.stacks.co/write-smart-contracts/clarity-overview) for the Stacks blockchain.

### Deployment Notes

* Only deploy via audited tools or with multisig protection for the contract owner.
* Ensure `tx-sender` matches expected OWNER principal in `CONTRACT_OWNER`.
