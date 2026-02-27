---
title: "Setting up WCB billing"
category: getting-started
slug: setting-up-wcb-billing
description: "Configure your Workers' Compensation Board contract, role, and skill codes during onboarding so Meritum knows which WCB forms you can submit."
priority: 1
last_reviewed: 2026-02-25
review_cycle: on-change
type: procedural
---

Workers' Compensation Board (WCB) billing is an optional onboarding step. If you treat injured workers and bill WCB Alberta directly, you configure your WCB credentials in Step 5 of the onboarding wizard. If you only bill Alberta Health Care Insurance Plan (AHCIP), skip this step and move on; you can always add WCB billing later from your account settings.

## What you need before you start

WCB Alberta assigns each contracted physician a **Contract ID**, a **Role code**, and a **Skill code**. These three values together determine which WCB form types you are permitted to submit. You can find them on your WCB Alberta contract documentation or by contacting WCB Alberta directly.

- **Contract ID** is a six-digit number (for example, 000001) that identifies your contract classification with WCB Alberta.
- **Role code** describes your clinical capacity under that contract: GP (General Practitioner), SP (Specialist), OIS (Occupational Injury Service Physician), NP (Nurse Practitioner), and others.
- **Skill code** is a specialty or service classification that WCB uses for reporting and routing.

The Contract ID and Role code combination controls which forms you can file. For example, a GP under Contract 000001 can submit a Physician First Report (C050E) and a Medical Invoice (C568), while an OIS physician under Contract 000053 can submit the OIS Physician First Report (C050S) instead. Meritum enforces this permission matrix automatically; when you create a WCB claim, the form type dropdown only shows forms your configuration allows.

## Adding your WCB configuration

1. In Step 5 of the onboarding wizard, enter your **Contract ID** in the field provided.
2. Enter your **Role code**. This must match the role WCB Alberta assigned to you under that contract.
3. Enter your **Skill code**.
4. Click **Continue**. Meritum validates your entries and saves the configuration.

Once saved, Meritum calculates your permitted form types from the Contract ID and Role code and stores them with your profile.

## Multiple Contract IDs

Some physicians hold more than one WCB contract. This is common when you bill under a general practice contract for standard injury reports and also participate in an Occupational Injury Service (OIS) clinic under a separate contract. Each Contract ID and Role code pairing has its own set of permitted forms, so you need a separate WCB configuration for each.

You can add additional WCB configurations after onboarding in your account settings under **WCB Billing**. When you create a WCB claim, Meritum uses your default configuration unless you select a different one during claim entry.

## What happens next

With your WCB configuration saved, you can create and submit WCB claims through Meritum. The platform supports all eight WCB form types: initial reports (C050E, C050S), progress reports (C151, C151S), consultation reports (C568A), medical invoices (C568), supplies invoices (C569), and invoice corrections (C570). Which of these appear for you depends on your Contract ID and Role code.

For a full breakdown of WCB form types and how they relate to each other, see [WCB Alberta billing for physicians](/help-centre/billing-reference/wcb-alberta-billing-for-physicians). When you are ready to file your first WCB claim, see [Submitting WCB claims](/help-centre/submitting-claims/submitting-wcb-claims).
