---
title: "How Meritum protects your data"
category: security-compliance
slug: how-meritum-protects-your-data
description: "Overview of Meritum's security measures: encryption, mandatory MFA, session controls, Canadian hosting, audit logging, and backup procedures."
priority: 3
last_reviewed: 2026-02-25
review_cycle: annual
type: reference
---

Meritum stores and transmits protected health information under the Health Information Act (HIA), so security is built into every layer of the platform. This article explains what protections are in place and what they mean for your practice.

## Encryption

All data stored in Meritum is encrypted at rest using AES-256, the same encryption standard used by major financial institutions. This means that even if someone gained physical access to the storage hardware, they could not read your patient records, claim data, or account information without the encryption keys.

All connections between your browser and Meritum use Transport Layer Security (TLS) 1.3, the current strongest version of the protocol that secures web traffic. This applies to every page, every API call, and every file upload. There is no unencrypted path into the platform.

Claim files transmitted to Alberta Health through H-Link are also encrypted before leaving Meritum's infrastructure. Your data is never in transit unprotected.

## Mandatory two-factor authentication

Every Meritum account requires Time-based One-Time Password (TOTP) two-factor authentication. There is no option to skip this step. When you create your account, you scan a QR code with an authenticator app (such as Google Authenticator, Authy, or 1Password) and enter a six-digit code to verify the setup. You also receive ten one-time recovery codes to store securely in case you lose access to your authenticator app.

Each time you sign in, you enter your password and then a six-digit code from your authenticator app. This means that a stolen password alone is not enough to access your account; an attacker would also need your phone or authenticator device.

Delegates who access your account on your behalf are also required to set up two-factor authentication on their own accounts.

## Session security

Once you sign in, your session is governed by two expiry rules:

1. **Absolute expiry**: every session ends after 24 hours, regardless of activity. You will need to sign in again.
2. **Idle expiry**: if you are inactive for 60 minutes, your session ends automatically. This protects your account if you walk away from your computer without signing out.

You can view and revoke active sessions from your account settings. If you sign in from a new device and want to end all other sessions, you can do so remotely. This is useful if you suspect your credentials have been compromised or if you left a session open on a shared computer.

Multiple concurrent sessions are allowed, so you can be signed in on your office computer and your phone at the same time without one session ending the other.

## Access controls

Meritum uses role-based permissions to control what each user can do. As a physician, you have full access to your own data. Delegates you invite receive only the specific permissions you grant them; for example, a delegate with claim viewing permission cannot create or modify claims unless you explicitly allow it.

Every query that retrieves patient or claim data is scoped to your physician account at the database level. There is no API call, URL manipulation, or software defect that could return another physician's records. This tenant isolation is enforced in the database layer itself, not just in the application interface.

## Canadian data residency

All Meritum data is stored on managed infrastructure in Toronto, Canada. This includes the database, file storage, backups, and application servers. No patient data, claim data, or physician data is processed or stored outside Canada at any point.

This is a requirement of the HIA and a commitment Meritum makes to every physician on the platform. For more on how this works, see [Canadian data residency](/help-centre/security-compliance/canadian-data-residency).

## Audit logging

Every access to patient and claim data is logged. Every state change on a claim, patient record, provider profile, or delegate relationship produces an audit record that captures who made the change, when, and what changed. These logs are append-only; they cannot be modified or deleted by anyone, including Meritum staff.

Audit logs support compliance with HIA requirements around access tracking and are available if you ever need to demonstrate who accessed a patient's information and when.

## Backup and recovery

Your data is backed up automatically on a continuous basis. Backups are encrypted and stored separately from the primary database, also within Canadian infrastructure. In the event of a hardware failure or other disruption, the platform can restore to a recent point in time.

Meritum targets 99.9% API availability. Scheduled maintenance windows are announced in advance through in-app notifications and do not affect stored data.

## Your role in security

The platform handles encryption, access controls, and monitoring, but some security practices depend on you:

- Use a strong, unique password for your Meritum account
- Store your recovery codes in a safe location separate from your authenticator device
- Review your active sessions periodically and revoke any you do not recognize
- Grant delegates only the permissions they need for their role

For details on Meritum's obligations under Alberta's Health Information Act, see [HIA compliance and the Information Manager Agreement](/help-centre/security-compliance/hia-compliance-and-the-information-manager-agreement).
