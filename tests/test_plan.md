# SecureChain Test Cases

## Test Environment
- OS: Windows 10
- Runtime: Python 3.10+ recommended
- Browser: Chrome/Edge latest
- Database: SQLite (`database.db`)

## Test Data Setup
- Admin account auto-seeded:
  - Username: `admin`
  - Password: `admin123!`
- Student accounts:
  - `alice` / `AlicePass1!`
  - `bob` / `BobPass1!`

## Test Case 1: Login Success
- **Objective:** Verify valid credentials allow login.
- **Precondition:** User account exists.
- **Steps:**
  1. Open `/login`.
  2. Enter valid username/password.
  3. Submit form.
- **Expected Result:**
  - Redirect to dashboard.
  - Session cookie created.
  - Log entry written for successful login.

## Test Case 2: Login Failure
- **Objective:** Verify invalid credentials are rejected.
- **Steps:**
  1. Open `/login`.
  2. Enter valid username with wrong password.
  3. Submit.
- **Expected Result:**
  - User stays on login page.
  - Safe error message shown.
  - Failed login action logged.

## Test Case 3: Send Transaction Success
- **Objective:** Verify tokens transfer securely.
- **Precondition:** Sender has enough balance.
- **Steps:**
  1. Login as `alice`.
  2. Open `/send`.
  3. Send `10` tokens to `bob`.
- **Expected Result:**
  - Sender balance decreases by 10.
  - Receiver balance increases by 10.
  - Transaction inserted in DB.
  - Blockchain block appended.
  - Action logs created for both users.

## Test Case 4: Invalid Input Rejection
- **Objective:** Validate input validation controls.
- **Steps:**
  1. Submit send form with negative amount (`-10`).
  2. Submit send form with non-numeric amount (`abc`).
  3. Submit invalid receiver username (`@@bad`).
- **Expected Result:**
  - Request rejected each time.
  - No DB updates occur.
  - User receives safe validation message.

## Test Case 5: Session Timeout
- **Objective:** Verify inactivity timeout works.
- **Steps:**
  1. Login as student.
  2. Wait longer than configured timeout (5 minutes).
  3. Access `/dashboard`.
- **Expected Result:**
  - Session is invalidated.
  - User is redirected to `/login`.
  - Expiry event logged.

## Test Case 6: Unauthorized Access
- **Objective:** Verify RBAC blocks non-admin access.
- **Steps:**
  1. Login as student.
  2. Open `/admin`.
- **Expected Result:**
  - Access denied.
  - Redirect to dashboard.
  - Unauthorized attempt logged.

## Test Case 7: Blockchain Integrity
- **Objective:** Verify chain consistency checks.
- **Steps:**
  1. Perform several valid transfers.
  2. Open admin dashboard and confirm chain status.
  3. (Optional controlled dev check) modify one block hash in memory and run `is_chain_valid`.
- **Expected Result:**
  - Normal flow: chain status is valid.
  - After tamper simulation: validity check fails.

## Test Case 8: Password Hashing
- **Objective:** Verify passwords are not plaintext.
- **Steps:**
  1. Register a new user.
  2. Inspect `users.password_hash` in SQLite.
  3. Verify string is bcrypt hash and not raw password.
- **Expected Result:**
  - Stored value starts with bcrypt signature (e.g., `$2b$`).
  - Raw password never appears in DB.

## Test Case 9: OTP Verification
- **Objective:** Verify two-factor login flow.
- **Steps:**
  1. Enter valid username/password at `/login`.
  2. Confirm redirect to `/verify-otp`.
  3. Enter displayed mock email OTP.
- **Expected Result:**
  - User is authenticated and redirected to dashboard.
  - OTP success is logged.
  - Invalid OTP attempt is rejected and logged.

## Test Case 10: Fraud Detection
- **Objective:** Verify suspicious transaction alerting.
- **Steps:**
  1. Login as user with sufficient balance.
  2. Send amount above threshold (`>200`).
- **Expected Result:**
  - Transaction proceeds.
  - Warning is shown.
  - Alert record appears in `alerts`.
  - Admin dashboard shows suspicious activity.

## Test Case 11: Failed Login Tracking
- **Objective:** Verify failed login telemetry.
- **Steps:**
  1. Attempt login with invalid password.
  2. Attempt OTP with invalid code.
- **Expected Result:**
  - Entries inserted into `failed_logins` with IP.
  - Failed login metric increments in `/admin/security`.

## Test Case 12: Encryption Validation
- **Objective:** Ensure sender/receiver/amount are encrypted at rest.
- **Steps:**
  1. Execute a transaction.
  2. Inspect DB values in `transactions.sender_enc`, `receiver_enc`, `amount_enc`.
- **Expected Result:**
  - Stored values are ciphertext.
  - Transactions page shows correctly decrypted values.

## Test Case 13: Blockchain Verification Endpoint
- **Objective:** Verify user-triggered chain integrity check.
- **Steps:**
  1. Click Verify Blockchain from navigation.
- **Expected Result:**
  - Flash message shows `VALID` or `TAMPERED`.
  - Verification event logged.

## Test Case 14: PDF Report Generation
- **Objective:** Verify audit report export.
- **Steps:**
  1. User clicks `Download Report` on transactions.
  2. Admin clicks reports export.
- **Expected Result:**
  - `transactions_report.pdf` downloads successfully.
  - Report includes user, amount, date, and hash.
  - Download action logged.

## Result Tracking Template
| Test Case | Status (Pass/Fail) | Tester | Date | Notes |
|---|---|---|---|---|
| Login Success |  |  |  |  |
| Login Failure |  |  |  |  |
| Send Transaction |  |  |  |  |
| Invalid Input |  |  |  |  |
| Session Timeout |  |  |  |  |
| Unauthorized Access |  |  |  |  |
| Blockchain Integrity |  |  |  |  |
| Password Hashing |  |  |  |  |
| OTP Verification |  |  |  |  |
| Fraud Detection |  |  |  |  |
| Failed Login Tracking |  |  |  |  |
| Encryption Validation |  |  |  |  |
| Blockchain Verification Endpoint |  |  |  |  |
| PDF Report Generation |  |  |  |  |
