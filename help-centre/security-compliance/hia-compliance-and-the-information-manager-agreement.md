---
title: "HIA compliance and the Information Manager Agreement"
category: security-compliance
slug: hia-compliance-and-the-information-manager-agreement
description: "What Alberta's Health Information Act requires of physicians and how the Information Manager Agreement formalises Meritum's data handling obligations."
priority: 3
last_reviewed: 2026-02-25
review_cycle: annual
type: reference
---

The Health Information Act (HIA) is Alberta's legislation governing how health information is collected, used, disclosed, and protected. As a physician using Meritum to submit claims, you are the custodian of your patients' health information under the HIA. Meritum is your Information Manager: a third party that processes health information on your behalf. The Information Manager Agreement (IMA) is the document that formalises this relationship and sets out exactly what Meritum is and is not permitted to do with the data you entrust to the platform.

## What the HIA requires

The HIA applies to all custodians of health information in Alberta, including physicians in private practice. It governs the entire lifecycle of health information: collection, use, disclosure, retention, and disposal. Custodians are responsible for safeguarding the information they hold, regardless of whether they process it themselves or engage a third party to do so.

Section 66 of the HIA specifically addresses the use of Information Managers. Before a custodian can allow a third party to process health information on their behalf, they must enter into an agreement with that third party. This agreement must set out the third party's obligations around data handling, security, confidentiality, and what happens when the relationship ends. The IMA between you and Meritum satisfies this requirement.

## What the IMA covers

The IMA is a binding agreement that includes the following provisions:

**Data handling obligations.** Meritum may only collect, use, and disclose health information as necessary to provide the billing services described in the agreement. The platform cannot use your patient data for any other purpose; not for marketing, analytics sold to third parties, research, or any activity outside the scope of claim submission and practice management.

**Encryption and technical safeguards.** All data is encrypted at rest (AES-256) and in transit (TLS 1.3). Access controls, mandatory two-factor authentication, and physician-scoped database queries ensure that your data is protected at every layer. For a full description of these measures, see [How Meritum protects your data](/help-centre/security-compliance/how-meritum-protects-your-data).

**Canadian data residency.** All health information processed by Meritum is stored and processed exclusively within Canada, on managed infrastructure located in Toronto. No data leaves the country at any point. This aligns with HIA requirements and Meritum's own operational commitments. For details on how residency is maintained, see [Canadian data residency](/help-centre/security-compliance/canadian-data-residency).

**Breach notification.** If Meritum becomes aware of a security incident involving your health information, the IMA requires prompt notification to you as the custodian. The notification includes a description of what happened, what data was affected, what steps Meritum has taken to contain the incident, and recommended actions on your part. This supports your own obligations under the HIA to notify the Office of the Information and Privacy Commissioner (OIPC) of Alberta when a breach occurs.

**Retention and disposal.** The IMA specifies how long data is retained and how it is disposed of when no longer needed. When your subscription ends or you request data deletion, Meritum follows a defined disposal process that ensures health information is permanently removed from all systems, including backups, within the timeframes set out in the agreement.

**Termination provisions.** If either party terminates the agreement, the IMA sets out how your data will be returned to you (via export) and subsequently deleted from Meritum's systems. You retain custody of your data at all times; Meritum holds it on your behalf and returns it on request.

## You are the custodian

This is the most important point. Under the HIA, the physician is always the custodian of their patients' health information. Meritum does not become a custodian by processing your claims. The IMA exists precisely to make this distinction clear: you control the data, and Meritum processes it according to your instructions and the terms of the agreement.

If a patient requests access to their health information, that request goes to you as the custodian. If the OIPC investigates a complaint, you are the responsible party, and the IMA ensures Meritum cooperates with any investigation and provides the records you need.

## How the IMA works during onboarding

You acknowledge the IMA during the Meritum onboarding process. The full text of the agreement is presented in a scrollable document viewer. After reading it, you select "I Acknowledge and Agree" to proceed. This is a digital acknowledgement; no printed signature is required.

Meritum stores a record of your acknowledgement that includes the template version of the IMA, a SHA-256 hash of the document you reviewed, the timestamp of your acknowledgement, and your IP address. This record ensures both parties can verify exactly which version of the IMA was acknowledged and when.

## Privacy Impact Assessment

A Privacy Impact Assessment (PIA) appendix is available for download during onboarding and from your account settings at any time. The PIA describes in detail how Meritum collects, uses, and protects health information, and is the document you would provide to the OIPC if requested during an audit or investigation. Reviewing the PIA is recommended but not required to complete onboarding.
