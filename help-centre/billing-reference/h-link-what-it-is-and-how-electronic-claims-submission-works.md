---
title: "H-Link: what it is and how electronic claims submission works"
category: billing-reference
slug: h-link-what-it-is-and-how-electronic-claims-submission-works
description: "Explains Alberta Health's H-Link electronic claims submission system, how accredited submitters transmit AHCIP claims, and what happens during transmission."
priority: 3
last_reviewed: 2026-02-25
review_cycle: quarterly
type: reference
---

H-Link is Alberta Health's electronic claims submission system for Alberta Health Care Insurance Plan (AHCIP) claims. It is the secure transmission channel that connects accredited submitters to Alberta Health's claims processing infrastructure. You do not interact with H-Link directly; Meritum is an accredited submitter and handles the formatting, encryption, and transmission of your claims on your behalf.

## What H-Link does

H-Link serves two functions. First, it receives claim submission files from accredited submitters every Thursday. Second, it returns assessment result files after Alberta Health has processed the submitted claims, typically on Friday. It is the only pathway for electronic AHCIP claim submission in Alberta; there is no alternative upload portal or direct submission option for individual physicians.

Every physician who bills AHCIP fee-for-service goes through H-Link, whether they realize it or not. The difference between billing platforms is which accredited submitter handles the transmission. When you use Meritum, your claims flow through Meritum's accredited H-Link connection.

## Accredited submitters

Alberta Health does not allow individual physicians to transmit claims through H-Link. Instead, it accredits organizations that meet its technical and security requirements. Accreditation involves demonstrating that the submitter can generate correctly formatted files, maintain secure transmission credentials, handle transmission failures gracefully, and protect the health information contained in claim files.

Each accredited submitter receives a submitter prefix: a short identifier that Alberta Health uses to associate incoming files with the submitting organization. Meritum holds its own submitter prefix and uses it when transmitting your claims. Your Business Arrangement (BA) number is included in the file itself, which is how Alberta Health links the claims back to you for payment.

## How claim files are structured

H-Link files follow a format defined in the Electronic Claims Submission Specifications Manual published by Alberta Health. Each file contains three parts:

**Header**: identifies the accredited submitter, the BA number, the submission date, and the batch sequence number. Alberta Health uses this to match the file to the correct submitter and physician.

**Claim records**: one record per claim. Each record contains the patient's Personal Health Number (PHN), date of birth, the Health Service Code (HSC), date of service, facility code, diagnostic code, modifiers, and the submitted fee. The fields map to specific positions and lengths defined in the specifications manual.

**Trailer**: a summary record containing the total number of claims in the file and the total submitted dollar value. Alberta Health uses this for integrity verification: if the trailer counts do not match the actual contents, the file is rejected before any claims are assessed.

If you hold multiple BA numbers (common for Physician Comprehensive Care Model physicians), each BA produces a separate file. This is an Alberta Health requirement; claims from different BAs cannot be mixed in a single submission file.

## Security and data protection

Claim files contain protected health information under the Health Information Act (HIA): patient PHNs, dates of birth, diagnostic codes, and service details. The transmission process is designed accordingly.

Files are encrypted at rest before transmission using AES-256 encryption. Transmission itself uses a secure channel: either SFTP with key-based authentication or TLS 1.3, depending on the configuration established during accreditation. H-Link credentials (the keys and certificates that authorize Meritum to transmit) are stored in a secrets management system, never in the database or application code.

All claim data is generated and stored on infrastructure located in Toronto, Canada, maintaining Canadian data residency as required by the HIA.

## What happens during transmission

When Meritum transmits your Thursday batch, the process follows a defined sequence. The platform connects to Alberta Health's H-Link endpoint using its accredited credentials, uploads the encrypted file, and receives a transmission acknowledgement. The platform logs the timestamp, file reference, record count, and transmission result.

If transmission fails (network interruption, endpoint unavailable), the platform retries automatically using exponential backoff: first at one minute, then five minutes, then fifteen minutes, then one hour. After four failed attempts, the submission is flagged for manual review and you are notified. This is rare; most transmissions succeed on the first attempt.

Once Alberta Health receives the file, it enters the assessment queue. Results are processed overnight and returned as an assessment file, which Meritum retrieves and uses to update your claim statuses on Friday.

## What you see in Meritum

From your perspective, the H-Link process is invisible. You create and validate claims during the week, and they sit in your submission queue. On Thursday, the platform handles everything: assembling the batch, formatting the H-Link file, encrypting it, transmitting it, and confirming the result. You receive a notification when submission completes and again when assessment results arrive.

The technical details described here are useful background if you want to understand what is happening behind the scenes, but they do not change your workflow. For the week-by-week rhythm of claim submission and assessment, see [The Thursday submission cycle explained](/help-centre/billing-reference/the-thursday-submission-cycle-explained). For a broader overview of how AHCIP billing works, see [AHCIP fee-for-service billing: how the system works](/help-centre/billing-reference/ahcip-fee-for-service-billing-how-the-system-works).
