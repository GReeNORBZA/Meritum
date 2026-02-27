---
title: "Submitting WCB claims"
category: submitting-claims
slug: submitting-wcb-claims
description: "How to create, validate, and submit Workers' Compensation Board claims through Meritum, including timing tiers, batch download, and return file processing."
priority: 2
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

Workers' Compensation Board (WCB) claim submission works differently from Alberta Health Care Insurance Plan (AHCIP). There is no Thursday batch cycle. Instead, you create WCB claims individually using guided forms, Meritum assembles them into an HL7 XML batch file, and you download that file and upload it to the myWCB portal yourself. Direct submission to WCB is planned for a future release.

## WCB form types

Each WCB claim uses a specific form type:

- **C050E / C050S**: Physician First Reports (initial injury reports for GPs and OIS physicians respectively).
- **C151 / C151S**: Progress Reports (follow-up reports on ongoing treatment).
- **C568**: Medical Invoice. **C568A**: Consultation Report.
- **C569**: Supplies Invoice. **C570**: Invoice Correction.

Which forms you can submit depends on your Contract ID and Role code. Meritum only shows the form types your configuration allows. If you have not set up WCB billing yet, see [Setting up WCB billing](/help-centre/getting-started/setting-up-wcb-billing).

## Timing tiers and why they matter

WCB fees vary based on how quickly you submit after the encounter. The tiers are:

1. **Same day**: highest fee. Submit the claim on the date of service.
2. **Next business day**: slightly lower fee.
3. **2 to 5 business days**: reduced fee.
4. **6 to 14 business days**: further reduced fee.
5. **15+ business days**: lowest fee tier.

Business days exclude weekends and Alberta's 10 statutory holidays. Meritum calculates which tier applies automatically based on the date of service and the date you submit. The claim form displays the current tier so you can see exactly where you stand before submitting. Earlier submission means higher reimbursement for the same service.

## Creating and submitting a WCB claim

1. Open the **Claims** page and click **New WCB Claim**.
2. Select the **form type** for this encounter.
3. Fill in the guided form. The fields vary by form type; Meritum walks you through each required field and validates your entries as you go.
4. Click **Save as Draft**. The validation engine checks your claim against WCB structural rules, timing calculations, and your contract permissions.
5. Review any flags or errors on the claim detail page and resolve them.
6. Once the claim is validated, approve it for submission (or let your submission preferences handle it automatically).

## Downloading the batch file

When you have one or more WCB claims ready for submission, Meritum assembles them into an HL7 XML batch file validated against the WCB XSD schema.

1. Go to **Submissions > WCB Batches**.
2. Click **Generate Batch**. Meritum bundles all approved WCB claims into a single XML file.
3. Click **Download** to save the file to your computer.
4. Log in to the **myWCB portal** and upload the batch file through their Electronic Injury Reporting interface.

## Processing the return file

After WCB processes your batch, you receive a return file from the myWCB portal containing the results for each claim.

1. Download the return file from the myWCB portal.
2. In Meritum, go to **Submissions > WCB Batches** and click **Upload Return File**.
3. Select the file. Meritum matches each result to the original claim and updates its status: accepted, rejected, or held for review.

This links WCB's responses back to your individual claims so you can see which were paid, which need corrections, and which require follow-up.

For a detailed breakdown of WCB form types, fee structures, and contract configurations, see [WCB Alberta billing for physicians](/help-centre/billing-reference/wcb-alberta-billing-for-physicians).
