---
title: "Importing encounters from your EMR"
category: submitting-claims
slug: importing-encounters-from-your-emr
description: "Upload a CSV or TSV export from your EMR to create draft claims in bulk, with saved field mapping templates for repeat imports."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

You can import encounters from your Electronic Medical Record (EMR) system instead of entering each claim by hand. Meritum accepts CSV and TSV files, maps your EMR's columns to the fields it needs, and creates draft claims ready for your review.

## Exporting from your EMR

Most EMR systems have a billing or encounters export option that produces a CSV (Comma-Separated Values) or TSV (Tab-Separated Values) file. The exact steps vary by vendor, but you are looking for an export that includes: patient identifier or Personal Health Number (PHN), health service code, date of service, diagnostic code, and any modifiers. Check your EMR's documentation or contact their support team if you cannot find the export function.

If you use **Connect Care**, go to your **My Billing Codes** report, run it for the date range you want, and export the results. Meritum recognises the Connect Care extract format automatically, so the field mapping step is handled for you.

## Uploading and mapping fields

1. Open the **Claims** page and click **Import from EMR**.
2. Select your file. Meritum detects the delimiter (comma, tab, or other) and whether the first row is a header row.
3. On the **Field Mapping** screen, match each column from your file to a Meritum claim field. Required fields are marked; optional fields like modifiers and referring physician can be left unmapped.
4. If this is your first import from this EMR, give the mapping a name (for example, "Wolf EMR Export" or "Med Access Billing"). Meritum saves it as a **field mapping template**. The next time you upload a file with the same column layout, select your saved template and skip straight to validation.
5. Click **Validate and Preview**.

## Reviewing the import summary

After validation, Meritum displays a summary of the file:

- **Total rows**: the number of data rows in the file.
- **Rows parsed**: rows that mapped successfully to claim fields.
- **Rows with warnings**: rows where the advice engine flagged a potential issue (for example, a health service code that rarely appears with the chosen diagnostic code). These rows still create draft claims; you can review the warnings later.
- **Rows rejected**: rows that failed validation entirely (missing required fields, unrecognised health service codes, invalid PHN format). Rejected rows are listed with the specific error so you can fix them in your EMR and re-import.
- **Potential duplicates**: rows that match an existing claim in Meritum by patient, health service code, and date of service. Duplicates are flagged but not automatically discarded; you decide whether to keep or skip them.

Review the summary, then click **Confirm Import** to create the claims.

## After the import

Imported claims land in your **Unsubmitted** queue with **Draft** status, just like claims you [create manually](/help-centre/submitting-claims/creating-claims-manually). Each one goes through the same validation engine and advice engine checks before it can move to Queued status. Open any imported claim to review its details, resolve flags, or make corrections.

Your saved field mapping templates appear under **Settings > Import Templates**. You can rename, edit, or delete them at any time. Once your template is dialled in, a weekly import takes less than a minute: upload, select template, confirm.
