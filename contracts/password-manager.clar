;; Decentralized Password Manager - Core Contract
;; Production-ready secure credential storage with multi-device sync and social recovery

;; ===========================================
;; CONSTANTS & ERROR CODES
;; ===========================================

(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-DEVICE (err u101))
(define-constant ERR-DEVICE-LIMIT-REACHED (err u102))
(define-constant ERR-VAULT-NOT-FOUND (err u103))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u104))
(define-constant ERR-INVALID-RECOVERY-GUARDIAN (err u105))
(define-constant ERR-INSUFFICIENT-GUARDIANS (err u106))
(define-constant ERR-RECOVERY-NOT-INITIATED (err u107))
(define-constant ERR-RECOVERY-EXPIRED (err u108))
(define-constant ERR-GUARDIAN-ALREADY-APPROVED (err u109))
(define-constant ERR-INVALID-SHARING-PERMISSION (err u110))

;; Limits and timeouts
(define-constant MAX-DEVICES-PER-USER u10)
(define-constant MIN-RECOVERY-GUARDIANS u3)
(define-constant RECOVERY-TIMEOUT-BLOCKS u144) ;; ~24 hours
(define-constant SHARE-EXPIRY-BLOCKS u1008) ;; ~1 week

;; ===========================================
;; DATA STRUCTURES
;; ===========================================

;; User vault metadata
(define-map user-vaults
    principal
    {
        master-key-hash: (buff 32),
        device-count: uint,
        last-sync-block: uint,
        recovery-guardians: (list 10 principal),
        is-active: bool
    }
)

;; Device management for multi-device sync
(define-map user-devices
    { user: principal, device-id: (string-ascii 64) }
    {
        device-public-key: (buff 33),
        encrypted-master-key: (buff 256),
        last-active-block: uint,
        is-authorized: bool
    }
)

;; Encrypted credential storage
(define-map credentials
    { user: principal, credential-id: (string-ascii 128) }
    {
        encrypted-data: (buff 512),
        metadata-hash: (buff 32),
        last-modified-block: uint,
        device-id: (string-ascii 64)
    }
)

;; Social recovery system
(define-map recovery-requests
    principal
    {
        new-master-key-hash: (buff 32),
        initiator-device: (string-ascii 64),
        approved-guardians: (list 10 principal),
        expiry-block: uint,
        is-active: bool
    }
)

;; Secure sharing system
(define-map shared-credentials
    { from-user: principal, to-user: principal, share-id: (string-ascii 128) }
    {
        encrypted-data: (buff 512),
        permissions: (string-ascii 32), ;; "read-only" or "full-access"
        expiry-block: uint,
        is-active: bool
    }
)

;; Track user device list for enumeration
(define-map user-device-list
    principal
    (list 10 (string-ascii 64))
)

;; ===========================================
;; VAULT MANAGEMENT
;; ===========================================

;; Initialize user vault with first device
(define-public (initialize-vault
    (master-key-hash (buff 32))
    (device-id (string-ascii 64))
    (device-public-key (buff 33))
    (encrypted-master-key (buff 256))
    (recovery-guardians (list 10 principal)))
    (let (
        (user tx-sender)
    )
        ;; Validate guardian count
        (asserts! (>= (len recovery-guardians) MIN-RECOVERY-GUARDIANS) ERR-INSUFFICIENT-GUARDIANS)

        ;; Ensure vault doesn't already exist
        (asserts! (is-none (map-get? user-vaults user)) ERR-NOT-AUTHORIZED)

        ;; Create vault
        (map-set user-vaults user {
            master-key-hash: master-key-hash,
            device-count: u1,
            last-sync-block: stacks-block-height,
            recovery-guardians: recovery-guardians,
            is-active: true
        })

        ;; Register first device
        (map-set user-devices { user: user, device-id: device-id } {
            device-public-key: device-public-key,
            encrypted-master-key: encrypted-master-key,
            last-active-block: stacks-block-height,
            is-authorized: true
        })

        ;; Initialize device list
        (map-set user-device-list user (list device-id))

        (ok true)
    )
)

;; Add new device to existing vault
(define-public (add-device
    (device-id (string-ascii 64))
    (device-public-key (buff 33))
    (encrypted-master-key (buff 256))
    (authorizing-device-id (string-ascii 64)))
    (let (
        (user tx-sender)
        (vault-info (unwrap! (map-get? user-vaults user) ERR-VAULT-NOT-FOUND))
        (authorizing-device (unwrap! (map-get? user-devices { user: user, device-id: authorizing-device-id }) ERR-INVALID-DEVICE))
    )
        ;; Verify authorizing device is valid and authorized
        (asserts! (get is-authorized authorizing-device) ERR-NOT-AUTHORIZED)

        ;; Check device limit
        (asserts! (< (get device-count vault-info) MAX-DEVICES-PER-USER) ERR-DEVICE-LIMIT-REACHED)

        ;; Add new device
        (map-set user-devices { user: user, device-id: device-id } {
            device-public-key: device-public-key,
            encrypted-master-key: encrypted-master-key,
            last-active-block: stacks-block-height,
            is-authorized: true
        })

        ;; Update vault info
        (map-set user-vaults user (merge vault-info {
            device-count: (+ (get device-count vault-info) u1),
            last-sync-block: stacks-block-height
        }))

        ;; Update device list
        (let ((current-devices (default-to (list) (map-get? user-device-list user))))
            (map-set user-device-list user (unwrap! (as-max-len? (append current-devices device-id) u10) ERR-DEVICE-LIMIT-REACHED))
        )

        (ok true)
    )
)

;; ===========================================
;; CREDENTIAL MANAGEMENT
;; ===========================================

;; Store encrypted credential
(define-public (store-credential
    (credential-id (string-ascii 128))
    (encrypted-data (buff 512))
    (metadata-hash (buff 32))
    (device-id (string-ascii 64)))
    (let (
        (user tx-sender)
        (device (unwrap! (map-get? user-devices { user: user, device-id: device-id }) ERR-INVALID-DEVICE))
    )
        ;; Verify device is authorized
        (asserts! (get is-authorized device) ERR-NOT-AUTHORIZED)

        ;; Store credential
        (map-set credentials { user: user, credential-id: credential-id } {
            encrypted-data: encrypted-data,
            metadata-hash: metadata-hash,
            last-modified-block: stacks-block-height,
            device-id: device-id
        })

        ;; Update device last active
        (map-set user-devices { user: user, device-id: device-id }
            (merge device { last-active-block: stacks-block-height }))

        (ok true)
    )
)

;; Retrieve encrypted credential
(define-read-only (get-credential (user principal) (credential-id (string-ascii 128)))
    (map-get? credentials { user: user, credential-id: credential-id })
)

;; Delete credential
(define-public (delete-credential
    (credential-id (string-ascii 128))
    (device-id (string-ascii 64)))
    (let (
        (user tx-sender)
        (device (unwrap! (map-get? user-devices { user: user, device-id: device-id }) ERR-INVALID-DEVICE))
    )
        ;; Verify device is authorized
        (asserts! (get is-authorized device) ERR-NOT-AUTHORIZED)

        ;; Verify credential exists
        (asserts! (is-some (map-get? credentials { user: user, credential-id: credential-id })) ERR-CREDENTIAL-NOT-FOUND)

        ;; Delete credential
        (map-delete credentials { user: user, credential-id: credential-id })

        (ok true)
    )
)

;; ===========================================
;; SOCIAL RECOVERY SYSTEM
;; ===========================================

;; Initiate account recovery
(define-public (initiate-recovery
    (lost-account principal)
    (new-master-key-hash (buff 32))
    (new-device-id (string-ascii 64)))
    (let (
        (guardian tx-sender)
        (vault-info (unwrap! (map-get? user-vaults lost-account) ERR-VAULT-NOT-FOUND))
        (guardians (get recovery-guardians vault-info))
    )
        ;; Verify caller is a valid guardian
        (asserts! (is-some (index-of guardians guardian)) ERR-INVALID-RECOVERY-GUARDIAN)

        ;; Create recovery request
        (map-set recovery-requests lost-account {
            new-master-key-hash: new-master-key-hash,
            initiator-device: new-device-id,
            approved-guardians: (list guardian),
            expiry-block: (+ stacks-block-height RECOVERY-TIMEOUT-BLOCKS),
            is-active: true
        })

        (ok true)
    )
)

;; Guardian approval of recovery
(define-public (approve-recovery (lost-account principal))
    (let (
        (guardian tx-sender)
        (vault-info (unwrap! (map-get? user-vaults lost-account) ERR-VAULT-NOT-FOUND))
        (recovery-request (unwrap! (map-get? recovery-requests lost-account) ERR-RECOVERY-NOT-INITIATED))
        (guardians (get recovery-guardians vault-info))
        (approved-guardians (get approved-guardians recovery-request))
    )
        ;; Verify recovery is active and not expired
        (asserts! (get is-active recovery-request) ERR-RECOVERY-NOT-INITIATED)
        (asserts! (< stacks-block-height (get expiry-block recovery-request)) ERR-RECOVERY-EXPIRED)

        ;; Verify caller is a valid guardian
        (asserts! (is-some (index-of guardians guardian)) ERR-INVALID-RECOVERY-GUARDIAN)

        ;; Verify guardian hasn't already approved
        (asserts! (is-none (index-of approved-guardians guardian)) ERR-GUARDIAN-ALREADY-APPROVED)

        ;; Add guardian approval
        (let ((new-approved-list (unwrap! (as-max-len? (append approved-guardians guardian) u10) ERR-INSUFFICIENT-GUARDIANS)))
            (map-set recovery-requests lost-account
                (merge recovery-request { approved-guardians: new-approved-list }))

            ;; If enough guardians have approved, execute recovery
            (if (>= (len new-approved-list) MIN-RECOVERY-GUARDIANS)
                (execute-recovery lost-account)
                (ok true)
            )
        )
    )
)

;; Execute recovery after sufficient guardian approval
(define-private (execute-recovery (lost-account principal))
    (let (
        (recovery-request (unwrap! (map-get? recovery-requests lost-account) ERR-RECOVERY-NOT-INITIATED))
        (vault-info (unwrap! (map-get? user-vaults lost-account) ERR-VAULT-NOT-FOUND))
    )
        ;; Update vault with new master key
        (map-set user-vaults lost-account (merge vault-info {
            master-key-hash: (get new-master-key-hash recovery-request),
            device-count: u1,
            last-sync-block: stacks-block-height
        }))

        ;; Deactivate recovery request
        (map-set recovery-requests lost-account
            (merge recovery-request { is-active: false }))

        (ok true)
    )
)

;; ===========================================
;; SECURE SHARING
;; ===========================================

;; Share credential with another user
(define-public (share-credential
    (to-user principal)
    (share-id (string-ascii 128))
    (encrypted-data (buff 512))
    (permissions (string-ascii 32))
    (device-id (string-ascii 64)))
    (let (
        (from-user tx-sender)
        (device (unwrap! (map-get? user-devices { user: from-user, device-id: device-id }) ERR-INVALID-DEVICE))
    )
        ;; Verify device is authorized
        (asserts! (get is-authorized device) ERR-NOT-AUTHORIZED)

        ;; Verify target user has a vault
        (asserts! (is-some (map-get? user-vaults to-user)) ERR-VAULT-NOT-FOUND)

        ;; Validate permissions
        (asserts! (or (is-eq permissions "read-only") (is-eq permissions "full-access")) ERR-INVALID-SHARING-PERMISSION)

        ;; Create share
        (map-set shared-credentials { from-user: from-user, to-user: to-user, share-id: share-id } {
            encrypted-data: encrypted-data,
            permissions: permissions,
            expiry-block: (+ stacks-block-height SHARE-EXPIRY-BLOCKS),
            is-active: true
        })

        (ok true)
    )
)

;; Revoke shared credential
(define-public (revoke-share
    (to-user principal)
    (share-id (string-ascii 128)))
    (let (
        (from-user tx-sender)
        (share-key { from-user: from-user, to-user: to-user, share-id: share-id })
    )
        ;; Verify share exists
        (asserts! (is-some (map-get? shared-credentials share-key)) ERR-CREDENTIAL-NOT-FOUND)

        ;; Deactivate share
        (map-set shared-credentials share-key
            (merge (unwrap-panic (map-get? shared-credentials share-key)) { is-active: false }))

        (ok true)
    )
)

;; ===========================================
;; READ-ONLY FUNCTIONS
;; ===========================================

;; Get user vault info
(define-read-only (get-vault-info (user principal))
    (map-get? user-vaults user)
)

;; Get device info
(define-read-only (get-device-info (user principal) (device-id (string-ascii 64)))
    (map-get? user-devices { user: user, device-id: device-id })
)

;; Get user devices
(define-read-only (get-user-devices (user principal))
    (map-get? user-device-list user)
)

;; Get recovery request status
(define-read-only (get-recovery-status (user principal))
    (map-get? recovery-requests user)
)

;; Get shared credential
(define-read-only (get-shared-credential (from-user principal) (to-user principal) (share-id (string-ascii 128)))
    (let (
        (share (map-get? shared-credentials { from-user: from-user, to-user: to-user, share-id: share-id }))
    )
        (match share
            some-share (if (and (get is-active some-share) (< stacks-block-height (get expiry-block some-share)))
                          (some some-share)
                          none)
            none
        )
    )
)

;; Check if user is authorized guardian
(define-read-only (is-recovery-guardian (user principal) (potential-guardian principal))
    (match (map-get? user-vaults user)
        some-vault (is-some (index-of (get recovery-guardians some-vault) potential-guardian))
        false
    )
)
