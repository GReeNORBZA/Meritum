---
title: "Canadian data residency"
category: security-compliance
slug: canadian-data-residency
description: "Where Meritum stores and processes your data, why it stays in Canada, and how third-party services are kept separate from health information."
priority: 3
last_reviewed: 2026-02-25
review_cycle: annual
type: reference
---

All patient data, claim data, and physician data in Meritum is stored and processed exclusively within Canada. No health information leaves the country at any point, for any reason. This article explains what that means in practice, where your data lives, and how third-party services are handled.

## What Canadian data residency means

Canadian data residency means that every piece of health information you enter into Meritum is stored on infrastructure physically located in Canada, processed by servers running in Canada, and backed up to storage within Canada. There is no replication to data centres in the United States or any other jurisdiction. There is no fallback that routes traffic or data outside the country during outages or maintenance.

This applies to everything the platform handles: patient demographics, Personal Health Numbers (PHNs), claim records, assessment results, provider profiles, delegate relationships, file uploads, and audit logs. If it contains or relates to health information, it stays in Canada.

## Where the infrastructure is located

Meritum runs on DigitalOcean's managed infrastructure in Toronto, Ontario. This covers:

- **Database**: PostgreSQL, hosted on DigitalOcean Managed Databases in the Toronto region. This is where patient records, claims, provider profiles, and all structured data are stored. Encryption at rest is applied to the database and its automated backups.
- **Application servers**: the Meritum API and web application run on DigitalOcean App Platform in the Toronto region. All request processing happens here.
- **File storage**: uploaded documents (such as Workers' Compensation Board (WCB) attachments) are stored in DigitalOcean Spaces in the Toronto region, an S3-compatible object storage service. Files are encrypted at rest.
- **Backups**: automated database backups and file storage snapshots are retained within the same Toronto region. Backups never leave Canadian infrastructure.

DigitalOcean's Toronto data centre operates under Canadian law, including the Personal Information Protection and Electronic Documents Act (PIPEDA). Meritum selected this provider specifically because it offers a Canadian region with no cross-border data transfer requirements.

## Why this matters under the Health Information Act

Alberta's Health Information Act (HIA) governs how health information is collected, used, disclosed, and stored. The HIA requires that custodians (physicians) and their Information Managers (Meritum) protect health information with appropriate safeguards. Storing health information within Canada is one of those safeguards.

Section 66 of the HIA sets out the obligations for Information Managers, including the requirement that health information be handled according to the terms of the Information Manager Agreement (IMA). The IMA between you and Meritum explicitly commits to Canadian data residency. This commitment is not just a technical default; it is a contractual obligation.

If health information were stored outside Canada, it could become subject to foreign laws, including laws that compel disclosure to foreign governments. Keeping data in Canada means it is governed solely by Canadian and Alberta privacy legislation. For more on how the IMA formalises these obligations, see [HIA compliance and the Information Manager Agreement](/help-centre/security-compliance/hia-compliance-and-the-information-manager-agreement).

## How payment processing is handled

Meritum uses Stripe for subscription billing and payment processing. Stripe is a global payment provider and processes payment data on infrastructure outside Canada. However, Stripe never receives health information of any kind.

The only data sent to Stripe is the physician's name and email address for billing purposes. No patient data, no PHNs, no claim details, no health service codes, and no diagnostic information is shared with Stripe. Payment processing is entirely separate from health information processing.

Your credit card details are collected by Stripe's embedded payment form and go directly to Stripe's systems. Meritum never sees, stores, or processes your card number. This separation means that even the payment flow does not create a path for health information to leave Canada.

## How the advice engine is handled

Meritum's advice engine analyses your claim patterns to suggest corrections and optimisations. The language model that powers this analysis runs on DigitalOcean infrastructure in Toronto, the same Canadian region as the rest of the platform. No patient data or claim data is sent to external services for processing.

Before any claim data reaches the advice engine, identifying details such as patient names and PHNs are stripped. The engine works with health service codes, diagnostic codes, modifiers, and billing patterns rather than identifiable patient information. Even so, this processing happens entirely within Canadian infrastructure.

There are no calls to external language model providers, no data sent to cloud-based services outside Canada, and no third-party processing of health information. The advice engine is self-contained within Meritum's Canadian infrastructure.

## Summary

Every component that touches health information runs in Canada:

- **Database**: Toronto, Canada. Contains health information.
- **Application servers**: Toronto, Canada. Processes health information.
- **File storage**: Toronto, Canada. Contains health information.
- **Backups**: Toronto, Canada. Contains health information.
- **Advice engine**: Toronto, Canada. Processes de-identified health information.
- **Payment processing (Stripe)**: outside Canada. Receives physician name and email only; no health information.

For a broader overview of all security measures in place, see [How Meritum protects your data](/help-centre/security-compliance/how-meritum-protects-your-data).
