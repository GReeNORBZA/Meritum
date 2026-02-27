import { type FastifyInstance } from 'fastify';
import multipart from '@fastify/multipart';
import {
  createPatientSchema,
  updatePatientSchema,
  patientIdParamSchema,
  patientSearchQuerySchema,
  recentPatientsQuerySchema,
  importIdParamSchema,
  importMappingSchema,
  mergePreviewSchema,
  mergeExecuteSchema,
  exportIdParamSchema,
  patientAccessExportDownloadParamSchema,
  internalPatientIdParamSchema,
  validatePhnParamSchema,
  checkEligibilitySchema,
  overrideEligibilitySchema,
  bulkCheckEligibilitySchema,
  detectProvinceSchema,
} from '@meritum/shared/schemas/patient.schema.js';
import { patientCorrectionSchema } from '@meritum/shared/schemas/compliance.schema.js';
import {
  createPatientHandlers,
  createInternalPatientHandlers,
  type PatientHandlerDeps,
  type InternalPatientHandlerDeps,
} from './patient.handlers.js';

// ---------------------------------------------------------------------------
// Patient Routes
// ---------------------------------------------------------------------------

export async function patientRoutes(
  app: FastifyInstance,
  opts: { deps: PatientHandlerDeps },
) {
  const handlers = createPatientHandlers(opts.deps);

  // =========================================================================
  // Search Routes (must be registered before /:id to avoid param conflicts)
  // =========================================================================

  app.get('/api/v1/patients/search', {
    config: { auditLog: true },
    schema: { querystring: patientSearchQuerySchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW')],
    handler: handlers.searchHandler,
  });

  app.get('/api/v1/patients/recent', {
    config: { auditLog: true },
    schema: { querystring: recentPatientsQuerySchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW')],
    handler: handlers.recentHandler,
  });

  // =========================================================================
  // Patient CRUD Routes
  // =========================================================================

  app.post('/api/v1/patients', {
    schema: { body: createPatientSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_CREATE')],
    handler: handlers.createPatientHandler,
  });

  app.get('/api/v1/patients/:id', {
    config: { auditLog: true },
    schema: { params: patientIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW')],
    handler: handlers.getPatientHandler,
  });

  app.put('/api/v1/patients/:id', {
    schema: { body: updatePatientSchema, params: patientIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_EDIT')],
    handler: handlers.updatePatientHandler,
  });

  app.patch('/api/v1/patients/:id/correct', {
    schema: { body: patientCorrectionSchema, params: patientIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_EDIT')],
    handler: handlers.correctPatientHandler,
  });

  app.post('/api/v1/patients/:id/deactivate', {
    schema: { params: patientIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_EDIT')],
    handler: handlers.deactivateHandler,
  });

  app.post('/api/v1/patients/:id/reactivate', {
    schema: { params: patientIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_EDIT')],
    handler: handlers.reactivateHandler,
  });

  // =========================================================================
  // Patient Merge Routes
  // =========================================================================

  app.post('/api/v1/patients/merge/preview', {
    schema: { body: mergePreviewSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_EDIT')],
    handler: handlers.mergePreviewHandler,
  });

  app.post('/api/v1/patients/merge/execute', {
    schema: { body: mergeExecuteSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_EDIT')],
    handler: handlers.mergeExecuteHandler,
  });

  // =========================================================================
  // Patient Export Routes
  // =========================================================================

  app.post('/api/v1/patients/exports', {
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW', 'REPORT_EXPORT')],
    handler: handlers.requestExportHandler,
  });

  app.get('/api/v1/patients/exports/:id', {
    config: { auditLog: true },
    schema: { params: exportIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW', 'REPORT_EXPORT')],
    handler: handlers.exportStatusHandler,
  });

  // =========================================================================
  // Patient Access Request Export (IMA S74)
  // =========================================================================

  app.post('/api/v1/patients/:id/export', {
    config: { auditLog: true },
    schema: { params: patientIdParamSchema },
    preHandler: [app.authenticate, app.authorize('DATA_EXPORT')],
    handler: handlers.exportPatientHiHandler,
  });

  app.get('/api/v1/patients/:id/export/:exportId/download', {
    schema: { params: patientAccessExportDownloadParamSchema },
    preHandler: [app.authenticate, app.authorize('DATA_EXPORT')],
    handler: handlers.downloadPatientHiHandler,
  });

  // =========================================================================
  // Eligibility Verification Routes (FRD MVPADD-001 §B2)
  // =========================================================================

  app.post('/api/v1/patients/eligibility/check', {
    config: { auditLog: true },
    schema: { body: checkEligibilitySchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW')],
    handler: handlers.checkEligibilityHandler,
  });

  app.post('/api/v1/patients/eligibility/override', {
    config: { auditLog: true },
    schema: { body: overrideEligibilitySchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_EDIT')],
    handler: handlers.overrideEligibilityHandler,
  });

  app.post('/api/v1/patients/eligibility/bulk-check', {
    config: { auditLog: true },
    schema: { body: bulkCheckEligibilitySchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW')],
    handler: handlers.bulkCheckEligibilityHandler,
  });

  // =========================================================================
  // Province Detection Routes (FRD MVPADD-001 §3.2)
  // =========================================================================

  app.post('/api/v1/patients/province/detect', {
    config: { auditLog: true },
    schema: { body: detectProvinceSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_VIEW')],
    handler: handlers.detectProvinceHandler,
  });

  // =========================================================================
  // CSV Import Routes
  // =========================================================================

  // Register multipart for file uploads (10MB limit)
  await app.register(multipart, {
    limits: {
      fileSize: 10 * 1024 * 1024, // 10 MB
    },
  });

  app.post('/api/v1/patients/imports', {
    preHandler: [app.authenticate, app.authorize('PATIENT_IMPORT')],
    handler: handlers.uploadHandler,
  });

  app.get('/api/v1/patients/imports/:id/preview', {
    config: { auditLog: true },
    schema: { params: importIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_IMPORT')],
    handler: handlers.previewHandler,
  });

  app.put('/api/v1/patients/imports/:id/mapping', {
    schema: { body: importMappingSchema, params: importIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_IMPORT')],
    handler: handlers.mappingHandler,
  });

  app.post('/api/v1/patients/imports/:id/commit', {
    schema: { params: importIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_IMPORT')],
    handler: handlers.commitHandler,
  });

  app.get('/api/v1/patients/imports/:id', {
    config: { auditLog: true },
    schema: { params: importIdParamSchema },
    preHandler: [app.authenticate, app.authorize('PATIENT_IMPORT')],
    handler: handlers.statusHandler,
  });
}

// ---------------------------------------------------------------------------
// Internal Patient Routes (service-to-service, API key auth)
// ---------------------------------------------------------------------------

export async function internalPatientRoutes(
  app: FastifyInstance,
  opts: { deps: InternalPatientHandlerDeps },
) {
  const handlers = createInternalPatientHandlers(opts.deps);

  // GET /api/v1/internal/patients/:id/claim-context
  app.get('/api/v1/internal/patients/:id/claim-context', {
    schema: { params: internalPatientIdParamSchema },
    handler: handlers.claimContextHandler,
  });

  // GET /api/v1/internal/patients/validate-phn/:phn
  app.get('/api/v1/internal/patients/validate-phn/:phn', {
    schema: { params: validatePhnParamSchema },
    handler: handlers.validatePhnHandler,
  });
}
