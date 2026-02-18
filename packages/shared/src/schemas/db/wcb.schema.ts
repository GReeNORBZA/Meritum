// ============================================================================
// Domain 4.2: WCB Pathway — Drizzle DB Schema
// ============================================================================

import {
  pgTable,
  uuid,
  varchar,
  text,
  date,
  timestamp,
  smallint,
  integer,
  decimal,
  boolean,
  jsonb,
  index,
  uniqueIndex,
  unique,
  check,
} from 'drizzle-orm/pg-core';
import { sql } from 'drizzle-orm';
import { claims } from './claim.schema.js';
import { users } from './iam.schema.js';
import { providers } from './provider.schema.js';

// --- WCB Claim Details Table ---
// One row per WCB claim, linked 1:1 to base claims table.
// Contains general, practitioner, and claimant fields per WCB Electronic Injury Reporting spec.
// Practitioner and claimant fields are immutable snapshots at claim creation time —
// they reflect the state at submission, not live references to provider/patient records.
// PHI (patient PHN, names, addresses) — encrypted at rest via DO Managed DB.
// No direct physician_id column; physician scoping enforced via JOIN to claims.

export const wcbClaimDetails = pgTable(
  'wcb_claim_details',
  {
    // --- Primary Key ---
    wcbClaimDetailId: uuid('wcb_claim_detail_id').primaryKey().defaultRandom(),

    // --- General Fields ---
    claimId: uuid('claim_id')
      .notNull()
      .unique()
      .references(() => claims.claimId),
    formId: varchar('form_id', { length: 5 }).notNull(),
    submitterTxnId: varchar('submitter_txn_id', { length: 16 }).notNull(),
    wcbClaimNumber: varchar('wcb_claim_number', { length: 7 }),
    reportCompletionDate: date('report_completion_date', { mode: 'string' }).notNull(),
    additionalComments: text('additional_comments'),
    parentWcbClaimId: uuid('parent_wcb_claim_id').references(
      (): any => wcbClaimDetails.wcbClaimDetailId,
    ),

    // --- Practitioner Fields (immutable snapshot at claim creation) ---
    practitionerBillingNumber: varchar('practitioner_billing_number', { length: 8 }).notNull(),
    contractId: varchar('contract_id', { length: 10 }).notNull(),
    roleCode: varchar('role_code', { length: 10 }).notNull(),
    practitionerFirstName: varchar('practitioner_first_name', { length: 11 }).notNull(),
    practitionerMiddleName: varchar('practitioner_middle_name', { length: 11 }),
    practitionerLastName: varchar('practitioner_last_name', { length: 21 }).notNull(),
    skillCode: varchar('skill_code', { length: 10 }).notNull(),
    facilityType: varchar('facility_type', { length: 1 }).notNull(),
    clinicReferenceNumber: varchar('clinic_reference_number', { length: 8 }),
    billingContactName: varchar('billing_contact_name', { length: 30 }),
    faxCountryCode: varchar('fax_country_code', { length: 10 }),
    faxNumber: varchar('fax_number', { length: 24 }),

    // --- Claimant (Patient) Fields (immutable snapshot) ---
    patientNoPhnFlag: varchar('patient_no_phn_flag', { length: 1 }).notNull(),
    patientPhn: varchar('patient_phn', { length: 9 }),
    patientGender: varchar('patient_gender', { length: 1 }).notNull(),
    patientFirstName: varchar('patient_first_name', { length: 11 }).notNull(),
    patientMiddleName: varchar('patient_middle_name', { length: 11 }),
    patientLastName: varchar('patient_last_name', { length: 21 }).notNull(),
    patientDob: date('patient_dob', { mode: 'string' }).notNull(),
    patientAddressLine1: varchar('patient_address_line1', { length: 30 }).notNull(),
    patientAddressLine2: varchar('patient_address_line2', { length: 30 }),
    patientCity: varchar('patient_city', { length: 20 }).notNull(),
    patientProvince: varchar('patient_province', { length: 10 }),
    patientPostalCode: varchar('patient_postal_code', { length: 9 }),
    patientPhoneCountry: varchar('patient_phone_country', { length: 10 }),
    patientPhoneNumber: varchar('patient_phone_number', { length: 24 }),

    // --- Employer Fields (required for C050E/S, C151/S) ---
    employerName: varchar('employer_name', { length: 50 }),
    employerLocation: varchar('employer_location', { length: 100 }),
    employerCity: varchar('employer_city', { length: 20 }),
    employerProvince: varchar('employer_province', { length: 10 }),
    employerPhoneCountry: varchar('employer_phone_country', { length: 10 }),
    employerPhoneNumber: varchar('employer_phone_number', { length: 24 }),
    employerPhoneExt: varchar('employer_phone_ext', { length: 6 }),

    // --- Accident Fields ---
    workerJobTitle: varchar('worker_job_title', { length: 50 }),
    injuryDevelopedOverTime: varchar('injury_developed_over_time', { length: 1 }),
    dateOfInjury: date('date_of_injury', { mode: 'string' }).notNull(),
    injuryDescription: text('injury_description'),

    // --- Injury Assessment Fields (scalar — repeating entries in wcb_injuries) ---
    dateOfExamination: date('date_of_examination', { mode: 'string' }),
    symptoms: text('symptoms'),
    objectiveFindings: text('objective_findings'),
    currentDiagnosis: text('current_diagnosis'),
    previousDiagnosis: text('previous_diagnosis'),
    diagnosisChanged: varchar('diagnosis_changed', { length: 1 }),
    diagnosisChangedDesc: text('diagnosis_changed_desc'),
    diagnosticCode1: varchar('diagnostic_code_1', { length: 8 }),
    diagnosticCode2: varchar('diagnostic_code_2', { length: 8 }),
    diagnosticCode3: varchar('diagnostic_code_3', { length: 8 }),
    additionalInjuriesDesc: text('additional_injuries_desc'),
    dominantHand: varchar('dominant_hand', { length: 10 }),
    priorConditionsFlag: varchar('prior_conditions_flag', { length: 1 }),
    priorConditionsDesc: text('prior_conditions_desc'),
    referringPhysicianName: varchar('referring_physician_name', { length: 50 }),
    dateOfReferral: date('date_of_referral', { mode: 'string' }),

    // --- Treatment Plan Fields ---
    narcoticsPrescribed: varchar('narcotics_prescribed', { length: 1 }),
    treatmentPlanText: text('treatment_plan_text'),
    caseConfWcbManager: varchar('case_conf_wcb_manager', { length: 1 }),
    caseConfWcbPhysician: varchar('case_conf_wcb_physician', { length: 1 }),
    referralRtwProvider: varchar('referral_rtw_provider', { length: 1 }),
    consultationLetterFormat: varchar('consultation_letter_format', { length: 5 }),
    consultationLetterText: text('consultation_letter_text'),

    // --- Return to Work Fields (C050E/S, C151/S) ---
    missedWorkBeyondAccident: varchar('missed_work_beyond_accident', { length: 1 }),
    patientReturnedToWork: varchar('patient_returned_to_work', { length: 1 }),
    dateReturnedToWork: date('date_returned_to_work', { mode: 'string' }),
    modifiedHours: varchar('modified_hours', { length: 1 }),
    hoursCapablePerDay: smallint('hours_capable_per_day'),
    modifiedDuties: varchar('modified_duties', { length: 1 }),
    rtwHospitalized: varchar('rtw_hospitalized', { length: 1 }),
    rtwSelfReportedPain: varchar('rtw_self_reported_pain', { length: 1 }),
    rtwOpioidSideEffects: varchar('rtw_opioid_side_effects', { length: 1 }),
    rtwOtherRestrictions: text('rtw_other_restrictions'),
    estimatedRtwDate: date('estimated_rtw_date', { mode: 'string' }),
    rtwStatusChanged: varchar('rtw_status_changed', { length: 1 }),

    // --- Invoice Correction Fields (C570 Only) ---
    reassessmentComments: text('reassessment_comments'),

    // --- OIS Hand Grasping Assessment (C050S/C151S) ---
    graspRightLevel: varchar('grasp_right_level', { length: 10 }),
    graspRightProlonged: varchar('grasp_right_prolonged', { length: 1 }),
    graspRightRepetitive: varchar('grasp_right_repetitive', { length: 1 }),
    graspRightVibration: varchar('grasp_right_vibration', { length: 1 }),
    graspRightSpecify: varchar('grasp_right_specify', { length: 1 }),
    graspRightSpecificDesc: text('grasp_right_specific_desc'),
    graspLeftLevel: varchar('grasp_left_level', { length: 10 }),
    graspLeftProlonged: varchar('grasp_left_prolonged', { length: 1 }),
    graspLeftRepetitive: varchar('grasp_left_repetitive', { length: 1 }),
    graspLeftVibration: varchar('grasp_left_vibration', { length: 1 }),
    graspLeftSpecify: varchar('grasp_left_specify', { length: 1 }),
    graspLeftSpecificDesc: text('grasp_left_specific_desc'),

    // --- OIS Zone-Specific Lifting ---
    liftFloorToWaist: varchar('lift_floor_to_waist', { length: 10 }),
    liftFloorToWaistMax: varchar('lift_floor_to_waist_max', { length: 10 }),
    liftWaistToShoulder: varchar('lift_waist_to_shoulder', { length: 10 }),
    liftWaistToShoulderMax: varchar('lift_waist_to_shoulder_max', { length: 10 }),
    liftAboveShoulder: varchar('lift_above_shoulder', { length: 10 }),
    liftAboveShoulderMax: varchar('lift_above_shoulder_max', { length: 10 }),

    // --- OIS Directional Reaching ---
    reachAboveRightShoulder: varchar('reach_above_right_shoulder', { length: 10 }),
    reachBelowRightShoulder: varchar('reach_below_right_shoulder', { length: 10 }),
    reachAboveLeftShoulder: varchar('reach_above_left_shoulder', { length: 10 }),
    reachBelowLeftShoulder: varchar('reach_below_left_shoulder', { length: 10 }),

    // --- OIS Environmental Restrictions ---
    environmentRestricted: varchar('environment_restricted', { length: 1 }),
    envCold: varchar('env_cold', { length: 1 }),
    envHot: varchar('env_hot', { length: 1 }),
    envWet: varchar('env_wet', { length: 1 }),
    envDry: varchar('env_dry', { length: 1 }),
    envDust: varchar('env_dust', { length: 1 }),
    envLighting: varchar('env_lighting', { length: 1 }),
    envNoise: varchar('env_noise', { length: 1 }),

    // --- OIS Assessment Summary ---
    oisReviewedWithPatient: varchar('ois_reviewed_with_patient', { length: 1 }),
    oisFitnessAssessment: varchar('ois_fitness_assessment', { length: 10 }),
    oisEstimatedRtwDate: date('ois_estimated_rtw_date', { mode: 'string' }),
    oisRtwLevel: varchar('ois_rtw_level', { length: 10 }),
    oisFollowupRequired: varchar('ois_followup_required', { length: 1 }),
    oisFollowupDate: date('ois_followup_date', { mode: 'string' }),
    oisEmpModifiedWorkRequired: varchar('ois_emp_modified_work_required', { length: 1 }),
    oisEmpModifiedFromDate: date('ois_emp_modified_from_date', { mode: 'string' }),
    oisEmpModifiedToDate: date('ois_emp_modified_to_date', { mode: 'string' }),
    oisEmpModifiedAvailable: varchar('ois_emp_modified_available', { length: 1 }),
    oisEmpAvailableFromDate: date('ois_emp_available_from_date', { mode: 'string' }),
    oisEmpAvailableToDate: date('ois_emp_available_to_date', { mode: 'string' }),
    oisEmpComments: text('ois_emp_comments'),
    oisWorkerRtwDate: date('ois_worker_rtw_date', { mode: 'string' }),
    oisWorkerModifiedDuration: varchar('ois_worker_modified_duration', { length: 50 }),
    oisWorkerDiagnosisPlan: text('ois_worker_diagnosis_plan'),
    oisWorkerSelfCare: varchar('ois_worker_self_care', { length: 1 }),
    oisWorkerComments: text('ois_worker_comments'),
    oisHasFamilyPhysician: varchar('ois_has_family_physician', { length: 1 }),
    oisFamilyPhysicianName: varchar('ois_family_physician_name', { length: 50 }),
    oisFamilyPhysicianPhoneCountry: varchar('ois_family_physician_phone_country', { length: 10 }),
    oisFamilyPhysicianPhone: varchar('ois_family_physician_phone', { length: 24 }),
    oisFamilyPhysicianPlan: text('ois_family_physician_plan'),
    oisFamilyPhysicianSupport: varchar('ois_family_physician_support', { length: 10 }),
    oisFamilyPhysicianRtwDate: date('ois_family_physician_rtw_date', { mode: 'string' }),
    oisFamilyPhysicianTreatment: varchar('ois_family_physician_treatment', { length: 10 }),
    oisFamilyPhysicianModified: varchar('ois_family_physician_modified', { length: 10 }),
    oisFamilyPhysicianComments: text('ois_family_physician_comments'),

    // --- Opioid Management Fields (C151/C151S only) ---
    surgeryPast60Days: varchar('surgery_past_60_days', { length: 1 }),
    treatingMalignantPain: varchar('treating_malignant_pain', { length: 1 }),
    wcbAdvisedNoMmr: varchar('wcb_advised_no_mmr', { length: 1 }),
    sideEffectNausea: varchar('side_effect_nausea', { length: 1 }),
    sideEffectSleep: varchar('side_effect_sleep', { length: 1 }),
    sideEffectConstipation: varchar('side_effect_constipation', { length: 1 }),
    sideEffectEndocrine: varchar('side_effect_endocrine', { length: 1 }),
    sideEffectSweating: varchar('side_effect_sweating', { length: 1 }),
    sideEffectCognitive: varchar('side_effect_cognitive', { length: 1 }),
    sideEffectDryMouth: varchar('side_effect_dry_mouth', { length: 1 }),
    sideEffectFatigue: varchar('side_effect_fatigue', { length: 1 }),
    sideEffectDepression: varchar('side_effect_depression', { length: 1 }),
    sideEffectWorseningPain: varchar('side_effect_worsening_pain', { length: 1 }),
    abuseSocialDeterioration: varchar('abuse_social_deterioration', { length: 1 }),
    abuseUnsanctionedUse: varchar('abuse_unsanctioned_use', { length: 1 }),
    abuseAlteredRoute: varchar('abuse_altered_route', { length: 1 }),
    abuseOpioidSeeking: varchar('abuse_opioid_seeking', { length: 1 }),
    abuseOtherSources: varchar('abuse_other_sources', { length: 1 }),
    abuseWithdrawal: varchar('abuse_withdrawal', { length: 1 }),
    patientPainEstimate: smallint('patient_pain_estimate'),
    opioidReducingPain: varchar('opioid_reducing_pain', { length: 1 }),
    painReductionDesc: text('pain_reduction_desc'),
    clinicianFunctionEstimate: smallint('clinician_function_estimate'),

    // --- Timestamps ---
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
    updatedAt: timestamp('updated_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedBy: uuid('updated_by')
      .notNull()
      .references(() => users.userId),
    deletedAt: timestamp('deleted_at', { withTimezone: true }),
  },
  (table) => [
    // Unique submitter transaction ID (vendor prefix + sequence)
    uniqueIndex('wcb_claim_details_submitter_txn_id_uniq').on(
      table.submitterTxnId,
    ),

    // FK lookup: find WCB details by claim ID (unique constraint above covers uniqueness)
    index('wcb_claim_details_claim_id_idx').on(table.claimId),

    // Query by form type and WCB claim number (follow-up chain, claim lookup)
    index('wcb_claim_details_form_claim_number_idx').on(
      table.formId,
      table.wcbClaimNumber,
    ),

    // Follow-up chain traversal: find children of a parent WCB claim
    index('wcb_claim_details_parent_wcb_claim_id_idx').on(
      table.parentWcbClaimId,
    ),
  ],
);

// --- WCB Injuries Table ---
// 1-5 injury entries per WCB claim with Injury section.
// Each entry captures Part of Body (POB), Side of Body (SOB), and Nature of Injury (NOI).
// 382 exclusion matrix validated at the service layer, not at DB level.

export const wcbInjuries = pgTable(
  'wcb_injuries',
  {
    wcbInjuryId: uuid('wcb_injury_id').primaryKey().defaultRandom(),
    wcbClaimDetailId: uuid('wcb_claim_detail_id')
      .notNull()
      .references(() => wcbClaimDetails.wcbClaimDetailId),
    ordinal: smallint('ordinal').notNull(),
    partOfBodyCode: varchar('part_of_body_code', { length: 10 }).notNull(),
    sideOfBodyCode: varchar('side_of_body_code', { length: 10 }),
    natureOfInjuryCode: varchar('nature_of_injury_code', { length: 10 }).notNull(),
  },
  (table) => [
    unique('wcb_injuries_detail_ordinal_uniq').on(
      table.wcbClaimDetailId,
      table.ordinal,
    ),
    check(
      'wcb_injuries_ordinal_check',
      sql`${table.ordinal} BETWEEN 1 AND 5`,
    ),
    index('wcb_injuries_claim_detail_id_idx').on(table.wcbClaimDetailId),
  ],
);

// --- WCB Prescriptions Table ---
// 1-5 prescription entries when narcotics_prescribed = 'Y' on the parent claim detail.

export const wcbPrescriptions = pgTable(
  'wcb_prescriptions',
  {
    wcbPrescriptionId: uuid('wcb_prescription_id').primaryKey().defaultRandom(),
    wcbClaimDetailId: uuid('wcb_claim_detail_id')
      .notNull()
      .references(() => wcbClaimDetails.wcbClaimDetailId),
    ordinal: smallint('ordinal').notNull(),
    prescriptionName: varchar('prescription_name', { length: 50 }).notNull(),
    strength: varchar('strength', { length: 30 }).notNull(),
    dailyIntake: varchar('daily_intake', { length: 30 }).notNull(),
  },
  (table) => [
    unique('wcb_prescriptions_detail_ordinal_uniq').on(
      table.wcbClaimDetailId,
      table.ordinal,
    ),
    check(
      'wcb_prescriptions_ordinal_check',
      sql`${table.ordinal} BETWEEN 1 AND 5`,
    ),
    index('wcb_prescriptions_claim_detail_id_idx').on(table.wcbClaimDetailId),
  ],
);

// --- WCB Consultations Table ---
// 1-5 consultation/investigation entries per WCB claim with Treatment Plan.
// Category: CONREF (consultation referral) or INVE (investigation).

export const wcbConsultations = pgTable(
  'wcb_consultations',
  {
    wcbConsultationId: uuid('wcb_consultation_id').primaryKey().defaultRandom(),
    wcbClaimDetailId: uuid('wcb_claim_detail_id')
      .notNull()
      .references(() => wcbClaimDetails.wcbClaimDetailId),
    ordinal: smallint('ordinal').notNull(),
    category: varchar('category', { length: 10 }).notNull(),
    typeCode: varchar('type_code', { length: 10 }).notNull(),
    details: varchar('details', { length: 50 }).notNull(),
    expediteRequested: varchar('expedite_requested', { length: 1 }),
  },
  (table) => [
    unique('wcb_consultations_detail_ordinal_uniq').on(
      table.wcbClaimDetailId,
      table.ordinal,
    ),
    check(
      'wcb_consultations_ordinal_check',
      sql`${table.ordinal} BETWEEN 1 AND 5`,
    ),
    index('wcb_consultations_claim_detail_id_idx').on(table.wcbClaimDetailId),
  ],
);

// --- WCB Work Restrictions Table ---
// Up to 11 activity-type restriction entries per WCB claim.
// Unique per (wcb_claim_detail_id, activity_type).

export const wcbWorkRestrictions = pgTable(
  'wcb_work_restrictions',
  {
    wcbRestrictionId: uuid('wcb_restriction_id').primaryKey().defaultRandom(),
    wcbClaimDetailId: uuid('wcb_claim_detail_id')
      .notNull()
      .references(() => wcbClaimDetails.wcbClaimDetailId),
    activityType: varchar('activity_type', { length: 20 }).notNull(),
    restrictionLevel: varchar('restriction_level', { length: 10 }).notNull(),
    hoursPerDay: smallint('hours_per_day'),
    maxWeight: varchar('max_weight', { length: 10 }),
  },
  (table) => [
    unique('wcb_work_restrictions_detail_activity_uniq').on(
      table.wcbClaimDetailId,
      table.activityType,
    ),
    index('wcb_work_restrictions_claim_detail_id_idx').on(
      table.wcbClaimDetailId,
    ),
  ],
);

// --- WCB Invoice Lines Table ---
// 1-25 invoice line entries per WCB claim, used across all form types.
// Line types: STANDARD (C568/A basic), DATED (C568/A with date range),
// SUPPLY (C569), WAS/SHOULD_BE (C570 correction pairs).
// C570 Was/Should Be lines are linked via correction_pair_id.
// Amount stored as DECIMAL(10,2) — never floating point.

export const wcbInvoiceLines = pgTable(
  'wcb_invoice_lines',
  {
    wcbInvoiceLineId: uuid('wcb_invoice_line_id').primaryKey().defaultRandom(),
    wcbClaimDetailId: uuid('wcb_claim_detail_id')
      .notNull()
      .references(() => wcbClaimDetails.wcbClaimDetailId),
    invoiceDetailId: smallint('invoice_detail_id').notNull(),
    lineType: varchar('line_type', { length: 10 }).notNull(),
    healthServiceCode: varchar('health_service_code', { length: 7 }),
    diagnosticCode1: varchar('diagnostic_code_1', { length: 8 }),
    diagnosticCode2: varchar('diagnostic_code_2', { length: 8 }),
    diagnosticCode3: varchar('diagnostic_code_3', { length: 8 }),
    modifier1: varchar('modifier_1', { length: 6 }),
    modifier2: varchar('modifier_2', { length: 6 }),
    modifier3: varchar('modifier_3', { length: 6 }),
    calls: smallint('calls'),
    encounters: smallint('encounters'),
    dateOfServiceFrom: date('date_of_service_from', { mode: 'string' }),
    dateOfServiceTo: date('date_of_service_to', { mode: 'string' }),
    facilityTypeOverride: varchar('facility_type_override', { length: 1 }),
    skillCodeOverride: varchar('skill_code_override', { length: 10 }),
    invoiceDetailTypeCode: varchar('invoice_detail_type_code', { length: 10 }),
    invoiceDetailDesc: varchar('invoice_detail_desc', { length: 50 }),
    quantity: smallint('quantity'),
    supplyDescription: varchar('supply_description', { length: 50 }),
    amount: decimal('amount', { precision: 10, scale: 2 }),
    adjustmentIndicator: varchar('adjustment_indicator', { length: 10 }),
    billingNumberOverride: varchar('billing_number_override', { length: 8 }),
    correctionPairId: smallint('correction_pair_id'),
  },
  (table) => [
    unique('wcb_invoice_lines_detail_line_uniq').on(
      table.wcbClaimDetailId,
      table.invoiceDetailId,
    ),
    check(
      'wcb_invoice_lines_detail_id_check',
      sql`${table.invoiceDetailId} BETWEEN 1 AND 25`,
    ),
    index('wcb_invoice_lines_claim_detail_id_idx').on(table.wcbClaimDetailId),
  ],
);

// --- WCB Attachments Table ---
// Up to 3 file attachments per WCB claim, base64-encoded for HL7 XML inclusion.
// File content is PHI (clinical documents) — encrypted at rest via DO Managed DB + AES-256.
// Permitted file types: PDF, DOC, DOCX, JPG, PNG, TIF.
// File size validated at service layer before base64 encoding to prevent memory exhaustion.

export const wcbAttachments = pgTable(
  'wcb_attachments',
  {
    wcbAttachmentId: uuid('wcb_attachment_id').primaryKey().defaultRandom(),
    wcbClaimDetailId: uuid('wcb_claim_detail_id')
      .notNull()
      .references(() => wcbClaimDetails.wcbClaimDetailId),
    ordinal: smallint('ordinal').notNull(),
    fileName: varchar('file_name', { length: 255 }).notNull(),
    fileType: varchar('file_type', { length: 10 }).notNull(),
    fileContentB64: text('file_content_b64').notNull(),
    fileDescription: varchar('file_description', { length: 60 }).notNull(),
    fileSizeBytes: integer('file_size_bytes').notNull(),
  },
  (table) => [
    unique('wcb_attachments_detail_ordinal_uniq').on(
      table.wcbClaimDetailId,
      table.ordinal,
    ),
    check(
      'wcb_attachments_ordinal_check',
      sql`${table.ordinal} BETWEEN 1 AND 3`,
    ),
    index('wcb_attachments_claim_detail_id_idx').on(table.wcbClaimDetailId),
  ],
);

// --- WCB Batches Table ---
// Per-physician batch of WCB claims for submission.
// Tracks lifecycle from assembly through XML generation, upload, return file processing, and reconciliation.
// xml_file_path references AES-256 encrypted file on disk — never store plaintext XML in database.
// Return files stored encrypted for 7-year audit retention.

export const wcbBatches = pgTable(
  'wcb_batches',
  {
    wcbBatchId: uuid('wcb_batch_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    batchControlId: varchar('batch_control_id', { length: 50 }).notNull(),
    fileControlId: varchar('file_control_id', { length: 50 }).notNull(),
    status: varchar('status', { length: 20 }).notNull(),
    reportCount: integer('report_count').notNull(),
    xmlFilePath: varchar('xml_file_path', { length: 255 }),
    xmlFileHash: varchar('xml_file_hash', { length: 64 }),
    xsdValidationPassed: boolean('xsd_validation_passed'),
    xsdValidationErrors: jsonb('xsd_validation_errors'),
    uploadedAt: timestamp('uploaded_at', { withTimezone: true }),
    uploadedBy: uuid('uploaded_by').references(() => users.userId),
    returnFileReceivedAt: timestamp('return_file_received_at', { withTimezone: true }),
    returnFilePath: varchar('return_file_path', { length: 255 }),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
    createdBy: uuid('created_by')
      .notNull()
      .references(() => users.userId),
  },
  (table) => [
    index('wcb_batches_physician_status_idx').on(
      table.physicianId,
      table.status,
    ),
    uniqueIndex('wcb_batches_batch_control_id_uniq').on(table.batchControlId),
    uniqueIndex('wcb_batches_file_control_id_uniq').on(table.fileControlId),
  ],
);

// --- WCB Return Records Table ---
// One row per claim in a WCB return file. Links back to the batch and optionally to the original claim detail.
// submitter_txn_id used for matching return records to submitted claims.

export const wcbReturnRecords = pgTable(
  'wcb_return_records',
  {
    wcbReturnRecordId: uuid('wcb_return_record_id').primaryKey().defaultRandom(),
    wcbBatchId: uuid('wcb_batch_id')
      .notNull()
      .references(() => wcbBatches.wcbBatchId),
    wcbClaimDetailId: uuid('wcb_claim_detail_id').references(
      () => wcbClaimDetails.wcbClaimDetailId,
    ),
    reportTxnId: varchar('report_txn_id', { length: 20 }).notNull(),
    submitterTxnId: varchar('submitter_txn_id', { length: 16 }).notNull(),
    processedClaimNumber: varchar('processed_claim_number', { length: 7 }),
    claimDecision: varchar('claim_decision', { length: 20 }).notNull(),
    reportStatus: varchar('report_status', { length: 20 }).notNull(),
    txnSubmissionDate: date('txn_submission_date', { mode: 'string' }).notNull(),
    errors: jsonb('errors'),
  },
  (table) => [
    index('wcb_return_records_batch_id_idx').on(table.wcbBatchId),
    index('wcb_return_records_submitter_txn_id_idx').on(table.submitterTxnId),
  ],
);

// --- WCB Return Invoice Lines Table ---
// Per-invoice-line status from a WCB return record. Links to the return record.

export const wcbReturnInvoiceLines = pgTable(
  'wcb_return_invoice_lines',
  {
    wcbReturnInvoiceLineId: uuid('wcb_return_invoice_line_id')
      .primaryKey()
      .defaultRandom(),
    wcbReturnRecordId: uuid('wcb_return_record_id')
      .notNull()
      .references(() => wcbReturnRecords.wcbReturnRecordId),
    invoiceSequence: smallint('invoice_sequence').notNull(),
    serviceDate: date('service_date', { mode: 'string' }),
    healthServiceCode: varchar('health_service_code', { length: 7 }),
    invoiceStatus: varchar('invoice_status', { length: 20 }),
  },
  (table) => [
    index('wcb_return_invoice_lines_return_record_id_idx').on(
      table.wcbReturnRecordId,
    ),
  ],
);

// --- WCB Remittance Imports Table ---
// Tracks each remittance file import as a batch.
// One import per physician per file upload.

export const wcbRemittanceImports = pgTable(
  'wcb_remittance_imports',
  {
    remittanceImportId: uuid('remittance_import_id').primaryKey().defaultRandom(),
    physicianId: uuid('physician_id')
      .notNull()
      .references(() => providers.providerId),
    recordCount: integer('record_count').notNull().default(0),
    createdAt: timestamp('created_at', { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index('wcb_remittance_imports_physician_id_idx').on(table.physicianId),
  ],
);

// --- WCB Remittance Records Table ---
// Payment remittance records from WCB Alberta PaymentRemittanceRecord XML schema.
// 31 columns matching the WCB remittance specification.
// worker_phn is PHI — same protections as patient_phn (masked as 123****** in logs).
// Stored encrypted for 7-year audit retention.

export const wcbRemittanceRecords = pgTable(
  'wcb_remittance_records',
  {
    wcbRemittanceId: uuid('wcb_remittance_id').primaryKey().defaultRandom(),
    remittanceImportId: uuid('remittance_import_id')
      .notNull()
      .references(() => wcbRemittanceImports.remittanceImportId),
    wcbClaimDetailId: uuid('wcb_claim_detail_id').references(
      () => wcbClaimDetails.wcbClaimDetailId,
    ),
    reportWeekStart: date('report_week_start', { mode: 'string' }).notNull(),
    reportWeekEnd: date('report_week_end', { mode: 'string' }).notNull(),
    disbursementNumber: varchar('disbursement_number', { length: 8 }),
    disbursementType: varchar('disbursement_type', { length: 3 }),
    disbursementIssueDate: date('disbursement_issue_date', { mode: 'string' }),
    disbursementAmount: decimal('disbursement_amount', { precision: 11, scale: 2 }),
    disbursementRecipientBilling: varchar('disbursement_recipient_billing', { length: 8 }),
    disbursementRecipientName: varchar('disbursement_recipient_name', { length: 40 }),
    paymentPayeeBilling: varchar('payment_payee_billing', { length: 8 }).notNull(),
    paymentPayeeName: varchar('payment_payee_name', { length: 40 }).notNull(),
    paymentReasonCode: varchar('payment_reason_code', { length: 3 }).notNull(),
    paymentStatus: varchar('payment_status', { length: 3 }).notNull(),
    paymentStartDate: date('payment_start_date', { mode: 'string' }).notNull(),
    paymentEndDate: date('payment_end_date', { mode: 'string' }).notNull(),
    paymentAmount: decimal('payment_amount', { precision: 11, scale: 2 }).notNull(),
    billedAmount: decimal('billed_amount', { precision: 10, scale: 2 }),
    electronicReportTxnId: varchar('electronic_report_txn_id', { length: 20 }),
    claimNumber: varchar('claim_number', { length: 7 }),
    workerPhn: varchar('worker_phn', { length: 11 }),
    workerFirstName: varchar('worker_first_name', { length: 11 }),
    workerLastName: varchar('worker_last_name', { length: 21 }),
    serviceCode: varchar('service_code', { length: 7 }),
    modifier1: varchar('modifier_1', { length: 6 }),
    modifier2: varchar('modifier_2', { length: 6 }),
    modifier3: varchar('modifier_3', { length: 6 }),
    numberOfCalls: smallint('number_of_calls'),
    encounterNumber: smallint('encounter_number'),
    overpaymentRecovery: decimal('overpayment_recovery', { precision: 10, scale: 2 }),
  },
  (table) => [
    index('wcb_remittance_records_electronic_report_txn_id_idx').on(
      table.electronicReportTxnId,
    ),
    index('wcb_remittance_records_import_id_idx').on(table.remittanceImportId),
    index('wcb_remittance_records_claim_number_idx').on(table.claimNumber),
  ],
);

// --- Inferred Types ---

export type InsertWcbClaimDetail = typeof wcbClaimDetails.$inferInsert;
export type SelectWcbClaimDetail = typeof wcbClaimDetails.$inferSelect;

export type InsertWcbInjury = typeof wcbInjuries.$inferInsert;
export type SelectWcbInjury = typeof wcbInjuries.$inferSelect;

export type InsertWcbPrescription = typeof wcbPrescriptions.$inferInsert;
export type SelectWcbPrescription = typeof wcbPrescriptions.$inferSelect;

export type InsertWcbConsultation = typeof wcbConsultations.$inferInsert;
export type SelectWcbConsultation = typeof wcbConsultations.$inferSelect;

export type InsertWcbWorkRestriction = typeof wcbWorkRestrictions.$inferInsert;
export type SelectWcbWorkRestriction = typeof wcbWorkRestrictions.$inferSelect;

export type InsertWcbInvoiceLine = typeof wcbInvoiceLines.$inferInsert;
export type SelectWcbInvoiceLine = typeof wcbInvoiceLines.$inferSelect;

export type InsertWcbAttachment = typeof wcbAttachments.$inferInsert;
export type SelectWcbAttachment = typeof wcbAttachments.$inferSelect;

export type InsertWcbBatch = typeof wcbBatches.$inferInsert;
export type SelectWcbBatch = typeof wcbBatches.$inferSelect;

export type InsertWcbReturnRecord = typeof wcbReturnRecords.$inferInsert;
export type SelectWcbReturnRecord = typeof wcbReturnRecords.$inferSelect;

export type InsertWcbReturnInvoiceLine = typeof wcbReturnInvoiceLines.$inferInsert;
export type SelectWcbReturnInvoiceLine = typeof wcbReturnInvoiceLines.$inferSelect;

export type InsertWcbRemittanceImport = typeof wcbRemittanceImports.$inferInsert;
export type SelectWcbRemittanceImport = typeof wcbRemittanceImports.$inferSelect;

export type InsertWcbRemittanceRecord = typeof wcbRemittanceRecords.$inferInsert;
export type SelectWcbRemittanceRecord = typeof wcbRemittanceRecords.$inferSelect;
