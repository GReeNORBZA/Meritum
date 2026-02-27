---
title: "Exporting your data"
category: your-account
slug: exporting-your-data
description: "How to export your complete billing data from Meritum, including what the export contains, the download process, and the accountant export option."
priority: 2
last_reviewed: 2026-02-25
review_cycle: annual
type: procedural
---

You can export all of your data from Meritum at any time. The data portability export gives you a complete copy of everything in your account: claims, patients, audit history, and more. The export downloads as a ZIP archive containing CSV files, JSON files, and a README that explains the schema.

## What the export includes

The data portability export covers your entire account:

- **All claims** in every state (draft, submitted, assessed, rejected, paid, adjusted, written off) with full field data, including Alberta Health Care Insurance Plan (AHCIP) and Workers' Compensation Board (WCB) extension fields
- **All patients** with demographics from your patient registry
- **Claim audit history** recording every state change, edit, and action on every claim
- **Advice engine suggestions** with their acceptance or dismissal status and your reasons
- **Batch history** for all AHCIP and WCB submission batches
- **Provider profile** including your business arrangement (BA) numbers, practice locations, WCB configuration, and submission preferences

Each data type is exported as its own CSV file (readable by Excel, Google Sheets, or any spreadsheet tool) alongside a JSON copy for software that consumes structured data. The included README file documents every column in every file so the data is self-describing.

## How to request an export

1. Log in to Meritum and open **Account Settings** from the navigation menu.
2. Scroll to the **Data & Privacy** section and select **Export My Data**.
3. Optionally, set a password to encrypt the ZIP file. This is recommended if you plan to store the export on a shared drive or send it to someone else.
4. Select **Request Export**.

The export generates in the background. For most accounts this takes under a minute, but physicians with several years of claim history may wait a few minutes. You receive an in-app notification and an email when the export is ready.

## Downloading your export

Once the export finishes, you can download it from the same **Data & Privacy** section in your account settings, or from the link in your notification.

The download link is authenticated; you must be logged in to use it. The link expires after 72 hours. If it expires before you download the file, you can request a new export at no cost.

## After cancellation

If you cancel your subscription, your account enters a 30-day grace period after the billing period ends. During this window you can still log in, view your data, and request a data portability export. After the grace period ends, your data is permanently deleted. See [Cancelling your subscription](/help-centre/your-account/cancelling-your-subscription) for full details on the cancellation timeline.

## Accountant export

The data portability export contains everything, which is more than most accountants need. For tax preparation and bookkeeping, use the **accountant export** instead. It produces a focused financial summary covering paid claims for a specific period, with fields your accountant expects: date of service, health service code, fees submitted, fees assessed, payment date, BA number, and location.

The accountant export is available in three formats: CSV for import into accounting software, a PDF summary with totals broken down by BA and location, and a detailed PDF listing individual claims. You can generate an accountant export on demand from the **Reports** section, or set up automatic monthly generation on the 3rd business day of each month.
