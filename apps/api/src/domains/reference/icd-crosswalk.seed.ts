// ============================================================================
// ICD-10-CA to ICD-9 Crosswalk Seed Data
// Top 100 most common conversions used in Alberta physician billing.
// Idempotent: safe to re-run — records are inserted only for a new version.
// ============================================================================

import type { InsertIcdCrosswalk } from '@meritum/shared/schemas/db/reference.schema.js';

export interface IcdCrosswalkSeedEntry {
  icd10Code: string;
  icd10Description: string;
  icd9Code: string;
  icd9Description: string;
  matchQuality: string;
  isPreferred: boolean;
  notes: string | null;
}

/**
 * Top 100 ICD-10-CA to ICD-9 crosswalk entries commonly encountered
 * in Alberta Connect Care SCC extract conversions.
 *
 * match_quality values: EXACT, APPROXIMATE, PARTIAL, MANY_TO_ONE
 */
export const ICD_CROSSWALK_SEED: IcdCrosswalkSeedEntry[] = [
  // --- Primary Care / General Practice ---
  { icd10Code: 'J06.9', icd10Description: 'Acute upper respiratory infection, unspecified', icd9Code: '465', icd9Description: 'Acute upper respiratory infections of multiple or unspecified sites', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'J20.9', icd10Description: 'Acute bronchitis, unspecified', icd9Code: '466', icd9Description: 'Acute bronchitis and bronchiolitis', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'J18.9', icd10Description: 'Pneumonia, unspecified organism', icd9Code: '486', icd9Description: 'Pneumonia, organism unspecified', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'N39.0', icd10Description: 'Urinary tract infection, site not specified', icd9Code: '599', icd9Description: 'Other disorders of urethra and urinary tract', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 599.0 is more specific' },
  { icd10Code: 'I10', icd10Description: 'Essential (primary) hypertension', icd9Code: '401', icd9Description: 'Essential hypertension', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'E11.9', icd10Description: 'Type 2 diabetes mellitus without complications', icd9Code: '250', icd9Description: 'Diabetes mellitus', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 250.00 for type II without complication' },
  { icd10Code: 'E78.5', icd10Description: 'Hyperlipidemia, unspecified', icd9Code: '272', icd9Description: 'Disorders of lipoid metabolism', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 272.4 is more specific' },
  { icd10Code: 'F32.9', icd10Description: 'Major depressive disorder, single episode, unspecified', icd9Code: '311', icd9Description: 'Depressive disorder, not elsewhere classified', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'F41.1', icd10Description: 'Generalized anxiety disorder', icd9Code: '300', icd9Description: 'Anxiety, dissociative and somatoform disorders', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 300.02 is more specific' },
  { icd10Code: 'M54.5', icd10Description: 'Low back pain', icd9Code: '724', icd9Description: 'Other and unspecified disorders of back', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 724.2 is more specific (lumbago)' },

  // --- Musculoskeletal ---
  { icd10Code: 'M79.3', icd10Description: 'Panniculitis, unspecified', icd9Code: '729', icd9Description: 'Other disorders of soft tissues', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'M25.5', icd10Description: 'Pain in joint', icd9Code: '719', icd9Description: 'Other and unspecified disorders of joint', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 719.4 is more specific' },
  { icd10Code: 'M17.1', icd10Description: 'Primary osteoarthritis of knee', icd9Code: '715', icd9Description: 'Osteoarthrosis and allied disorders', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'M75.1', icd10Description: 'Rotator cuff syndrome', icd9Code: '726', icd9Description: 'Peripheral enthesopathies and allied syndromes', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'M54.2', icd10Description: 'Cervicalgia', icd9Code: '723', icd9Description: 'Other disorders of cervical region', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },

  // --- Cardiovascular ---
  { icd10Code: 'I25.1', icd10Description: 'Atherosclerotic heart disease', icd9Code: '414', icd9Description: 'Other forms of chronic ischemic heart disease', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'I48.9', icd10Description: 'Atrial fibrillation, unspecified', icd9Code: '427', icd9Description: 'Cardiac dysrhythmias', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 427.31 is more specific' },
  { icd10Code: 'I50.9', icd10Description: 'Heart failure, unspecified', icd9Code: '428', icd9Description: 'Heart failure', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'I63.9', icd10Description: 'Cerebral infarction, unspecified', icd9Code: '434', icd9Description: 'Occlusion of cerebral arteries', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'I21.9', icd10Description: 'Acute myocardial infarction, unspecified', icd9Code: '410', icd9Description: 'Acute myocardial infarction', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Respiratory ---
  { icd10Code: 'J44.1', icd10Description: 'COPD with acute exacerbation', icd9Code: '491', icd9Description: 'Chronic bronchitis', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'J45.9', icd10Description: 'Asthma, unspecified', icd9Code: '493', icd9Description: 'Asthma', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'J02.9', icd10Description: 'Acute pharyngitis, unspecified', icd9Code: '462', icd9Description: 'Acute pharyngitis', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'J01.9', icd10Description: 'Acute sinusitis, unspecified', icd9Code: '461', icd9Description: 'Acute sinusitis', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'J30.1', icd10Description: 'Allergic rhinitis due to pollen', icd9Code: '477', icd9Description: 'Allergic rhinitis', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Gastrointestinal ---
  { icd10Code: 'K21.0', icd10Description: 'GERD with esophagitis', icd9Code: '530', icd9Description: 'Diseases of esophagus', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'K59.0', icd10Description: 'Constipation', icd9Code: '564', icd9Description: 'Functional digestive disorders, not elsewhere classified', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'K58.9', icd10Description: 'Irritable bowel syndrome without diarrhea', icd9Code: '564', icd9Description: 'Functional digestive disorders, not elsewhere classified', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 564.1 is more specific' },
  { icd10Code: 'K29.7', icd10Description: 'Gastritis, unspecified', icd9Code: '535', icd9Description: 'Gastritis and duodenitis', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'A09', icd10Description: 'Infectious gastroenteritis and colitis, unspecified', icd9Code: '009', icd9Description: 'Ill-defined intestinal infections', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Endocrine ---
  { icd10Code: 'E03.9', icd10Description: 'Hypothyroidism, unspecified', icd9Code: '244', icd9Description: 'Acquired hypothyroidism', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'E05.9', icd10Description: 'Thyrotoxicosis, unspecified', icd9Code: '242', icd9Description: 'Thyrotoxicosis with or without goiter', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'E66.9', icd10Description: 'Obesity, unspecified', icd9Code: '278', icd9Description: 'Overweight, obesity and other hyperalimentation', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'E55.9', icd10Description: 'Vitamin D deficiency, unspecified', icd9Code: '268', icd9Description: 'Vitamin D deficiency', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'E87.6', icd10Description: 'Hypokalemia', icd9Code: '276', icd9Description: 'Disorders of fluid, electrolyte, and acid-base balance', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },

  // --- Dermatological ---
  { icd10Code: 'L30.9', icd10Description: 'Dermatitis, unspecified', icd9Code: '692', icd9Description: 'Contact dermatitis and other eczema', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'L40.0', icd10Description: 'Psoriasis vulgaris', icd9Code: '696', icd9Description: 'Psoriasis and similar disorders', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'L70.0', icd10Description: 'Acne vulgaris', icd9Code: '706', icd9Description: 'Diseases of sebaceous glands', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'B35.1', icd10Description: 'Tinea unguium', icd9Code: '110', icd9Description: 'Dermatophytosis', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'L50.9', icd10Description: 'Urticaria, unspecified', icd9Code: '708', icd9Description: 'Urticaria', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Genitourinary ---
  { icd10Code: 'N40.0', icd10Description: 'Benign prostatic hyperplasia without LUTS', icd9Code: '600', icd9Description: 'Hyperplasia of prostate', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'N20.0', icd10Description: 'Calculus of kidney', icd9Code: '592', icd9Description: 'Calculus of kidney and ureter', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'N76.0', icd10Description: 'Acute vaginitis', icd9Code: '616', icd9Description: 'Inflammatory disease of cervix, vagina, and vulva', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'N92.0', icd10Description: 'Excessive and frequent menstruation with regular cycle', icd9Code: '626', icd9Description: 'Disorders of menstruation and other abnormal bleeding', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'N95.1', icd10Description: 'Menopausal and female climacteric states', icd9Code: '627', icd9Description: 'Menopausal and postmenopausal disorders', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Neurological ---
  { icd10Code: 'G43.9', icd10Description: 'Migraine, unspecified', icd9Code: '346', icd9Description: 'Migraine', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'G40.9', icd10Description: 'Epilepsy, unspecified', icd9Code: '345', icd9Description: 'Epilepsy and recurrent seizures', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'G47.0', icd10Description: 'Insomnia', icd9Code: '780', icd9Description: 'General symptoms', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 780.52 is more specific' },
  { icd10Code: 'G56.0', icd10Description: 'Carpal tunnel syndrome', icd9Code: '354', icd9Description: 'Mononeuritis of upper limb and mononeuritis multiplex', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'G35', icd10Description: 'Multiple sclerosis', icd9Code: '340', icd9Description: 'Multiple sclerosis', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Ophthalmological ---
  { icd10Code: 'H10.9', icd10Description: 'Conjunctivitis, unspecified', icd9Code: '372', icd9Description: 'Disorders of conjunctiva', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'H40.1', icd10Description: 'Primary open-angle glaucoma', icd9Code: '365', icd9Description: 'Glaucoma', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'H25.9', icd10Description: 'Senile cataract, unspecified', icd9Code: '366', icd9Description: 'Cataract', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'H52.1', icd10Description: 'Myopia', icd9Code: '367', icd9Description: 'Disorders of refraction and accommodation', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },

  // --- ENT ---
  { icd10Code: 'H66.9', icd10Description: 'Otitis media, unspecified', icd9Code: '382', icd9Description: 'Suppurative and unspecified otitis media', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'H60.9', icd10Description: 'Otitis externa, unspecified', icd9Code: '380', icd9Description: 'Diseases of external ear', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'J35.0', icd10Description: 'Chronic tonsillitis', icd9Code: '474', icd9Description: 'Chronic disease of tonsils and adenoids', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Injury / Trauma ---
  { icd10Code: 'S62.5', icd10Description: 'Fracture of thumb', icd9Code: '816', icd9Description: 'Fracture of one or more phalanges of hand', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'S52.5', icd10Description: 'Fracture of lower end of radius', icd9Code: '813', icd9Description: 'Fracture of radius and ulna', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'S82.0', icd10Description: 'Fracture of patella', icd9Code: '822', icd9Description: 'Fracture of patella', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'S93.4', icd10Description: 'Sprain of ankle', icd9Code: '845', icd9Description: 'Sprains and strains of ankle and foot', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'S06.0', icd10Description: 'Concussion', icd9Code: '850', icd9Description: 'Concussion', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Mental Health ---
  { icd10Code: 'F10.1', icd10Description: 'Alcohol abuse', icd9Code: '305', icd9Description: 'Nondependent abuse of drugs', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'F17.2', icd10Description: 'Nicotine dependence', icd9Code: '305', icd9Description: 'Nondependent abuse of drugs', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 305.1 is more specific' },
  { icd10Code: 'F33.0', icd10Description: 'Recurrent depressive disorder, current episode mild', icd9Code: '296', icd9Description: 'Episodic mood disorders', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'F43.1', icd10Description: 'Post-traumatic stress disorder', icd9Code: '309', icd9Description: 'Adjustment reaction', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 309.81 is more specific' },
  { icd10Code: 'F90.0', icd10Description: 'ADHD, predominantly inattentive type', icd9Code: '314', icd9Description: 'Hyperkinetic syndrome of childhood', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },

  // --- Obstetric ---
  { icd10Code: 'O80', icd10Description: 'Single spontaneous delivery', icd9Code: '650', icd9Description: 'Normal delivery', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'O24.4', icd10Description: 'Gestational diabetes mellitus', icd9Code: '648', icd9Description: 'Other current conditions classifiable elsewhere of mother', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'O13', icd10Description: 'Gestational hypertension', icd9Code: '642', icd9Description: 'Hypertension complicating pregnancy', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'Z34.0', icd10Description: 'Supervision of normal first pregnancy', icd9Code: 'V22', icd9Description: 'Normal pregnancy', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Neoplasm ---
  { icd10Code: 'C50.9', icd10Description: 'Malignant neoplasm of breast, unspecified', icd9Code: '174', icd9Description: 'Malignant neoplasm of female breast', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'C61', icd10Description: 'Malignant neoplasm of prostate', icd9Code: '185', icd9Description: 'Malignant neoplasm of prostate', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'C34.9', icd10Description: 'Malignant neoplasm of bronchus or lung, unspecified', icd9Code: '162', icd9Description: 'Malignant neoplasm of trachea, bronchus, and lung', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'C18.9', icd10Description: 'Malignant neoplasm of colon, unspecified', icd9Code: '153', icd9Description: 'Malignant neoplasm of colon', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'D25.9', icd10Description: 'Leiomyoma of uterus, unspecified', icd9Code: '218', icd9Description: 'Uterine leiomyoma', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Infectious Disease ---
  { icd10Code: 'B34.9', icd10Description: 'Viral infection, unspecified', icd9Code: '079', icd9Description: 'Viral and chlamydial infection in conditions classified elsewhere', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'B37.3', icd10Description: 'Candidiasis of vulva and vagina', icd9Code: '112', icd9Description: 'Candidiasis', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'A56.0', icd10Description: 'Chlamydial infection of lower genitourinary tract', icd9Code: '099', icd9Description: 'Other venereal diseases', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'U07.1', icd10Description: 'COVID-19, virus identified', icd9Code: '079', icd9Description: 'Viral and chlamydial infection in conditions classified elsewhere', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'No direct ICD-9 equivalent for COVID-19' },

  // --- Hematological ---
  { icd10Code: 'D50.9', icd10Description: 'Iron deficiency anemia, unspecified', icd9Code: '280', icd9Description: 'Iron deficiency anemias', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'D64.9', icd10Description: 'Anemia, unspecified', icd9Code: '285', icd9Description: 'Other and unspecified anemias', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- Symptoms / Signs ---
  { icd10Code: 'R10.4', icd10Description: 'Other and unspecified abdominal pain', icd9Code: '789', icd9Description: 'Other symptoms involving abdomen and pelvis', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'R51', icd10Description: 'Headache', icd9Code: '784', icd9Description: 'Symptoms involving head and neck', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 784.0 is more specific' },
  { icd10Code: 'R05', icd10Description: 'Cough', icd9Code: '786', icd9Description: 'Symptoms involving respiratory system and other chest symptoms', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'R53.1', icd10Description: 'Weakness', icd9Code: '780', icd9Description: 'General symptoms', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 780.79 is more specific' },
  { icd10Code: 'R42', icd10Description: 'Dizziness and giddiness', icd9Code: '780', icd9Description: 'General symptoms', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 780.4 is more specific' },
  { icd10Code: 'R50.9', icd10Description: 'Fever, unspecified', icd9Code: '780', icd9Description: 'General symptoms', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 780.60 is more specific' },
  { icd10Code: 'R00.0', icd10Description: 'Tachycardia, unspecified', icd9Code: '785', icd9Description: 'Symptoms involving cardiovascular system', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'R07.9', icd10Description: 'Chest pain, unspecified', icd9Code: '786', icd9Description: 'Symptoms involving respiratory system and other chest symptoms', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'ICD-9 786.50 is more specific' },

  // --- Screening / Preventive ---
  { icd10Code: 'Z00.0', icd10Description: 'General adult medical examination', icd9Code: 'V70', icd9Description: 'General medical examination', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'Z12.1', icd10Description: 'Screening for neoplasm of intestinal tract', icd9Code: 'V76', icd9Description: 'Special screening for malignant neoplasms', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
  { icd10Code: 'Z23', icd10Description: 'Encounter for immunization', icd9Code: 'V05', icd9Description: 'Need for other prophylactic vaccination and inoculation', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'Z76.0', icd10Description: 'Encounter for issue of repeat prescription', icd9Code: 'V68', icd9Description: 'Encounters for administrative purposes', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },

  // --- Renal ---
  { icd10Code: 'N18.3', icd10Description: 'Chronic kidney disease, stage 3', icd9Code: '585', icd9Description: 'Chronic kidney disease', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'N17.9', icd10Description: 'Acute kidney failure, unspecified', icd9Code: '584', icd9Description: 'Acute kidney failure', matchQuality: 'EXACT', isPreferred: true, notes: null },

  // --- WCB-common injury codes ---
  { icd10Code: 'S83.5', icd10Description: 'Sprain of cruciate ligament of knee', icd9Code: '844', icd9Description: 'Sprains and strains of knee and leg', matchQuality: 'EXACT', isPreferred: true, notes: 'Common WCB claim' },
  { icd10Code: 'S43.4', icd10Description: 'Sprain of shoulder joint', icd9Code: '840', icd9Description: 'Sprains and strains of shoulder and upper arm', matchQuality: 'EXACT', isPreferred: true, notes: 'Common WCB claim' },
  { icd10Code: 'S13.4', icd10Description: 'Sprain of ligaments of cervical spine', icd9Code: '847', icd9Description: 'Sprains and strains of other and unspecified parts of back', matchQuality: 'APPROXIMATE', isPreferred: true, notes: 'Whiplash — common WCB claim' },
  { icd10Code: 'T14.0', icd10Description: 'Superficial injury of unspecified body region', icd9Code: '919', icd9Description: 'Superficial injury of other, multiple, and unspecified sites', matchQuality: 'EXACT', isPreferred: true, notes: null },
  { icd10Code: 'S60.0', icd10Description: 'Contusion of finger(s)', icd9Code: '923', icd9Description: 'Contusion of upper limb', matchQuality: 'APPROXIMATE', isPreferred: true, notes: null },
];

/**
 * Convert seed entries to Drizzle insert format.
 * Caller must supply the versionId.
 */
export function toInsertRecords(versionId: string): InsertIcdCrosswalk[] {
  return ICD_CROSSWALK_SEED.map((entry) => ({
    versionId,
    icd10Code: entry.icd10Code,
    icd10Description: entry.icd10Description,
    icd9Code: entry.icd9Code,
    icd9Description: entry.icd9Description,
    matchQuality: entry.matchQuality,
    isPreferred: entry.isPreferred,
    notes: entry.notes,
  }));
}
