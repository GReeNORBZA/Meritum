import { type FastifyRequest, type FastifyReply } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import {
  type UpdateProvider,
  type CreateBa,
  type UpdateBa,
  type BaIdParam,
  type CreateLocation,
  type UpdateLocation,
  type LocationIdParam,
  type CreateWcbConfig,
  type UpdateWcbConfig,
  type WcbConfigIdParam,
  type UpdateSubmissionPreferences,
  type UpdateHlinkConfig,
  type InviteDelegate,
  type UpdateDelegatePermissions,
  type DelegateRelIdParam,
  type AcceptInvitation,
  type SwitchContextParam,
  type ProviderIdParam,
  type BaForClaimQuery,
  type WcbConfigForFormQuery,
} from '@meritum/shared/schemas/provider.schema.js';
import {
  getProviderProfile,
  updateProviderProfile,
  getOnboardingStatus,
  completeOnboarding,
  addBa,
  updateBa,
  deactivateBa,
  listBas,
  addLocation,
  updateLocation,
  setDefaultLocation,
  deactivateLocation,
  listLocations,
  addWcbConfig,
  updateWcbConfig,
  removeWcbConfig,
  listWcbConfigs,
  getFormPermissions,
  getSubmissionPreferences,
  updateSubmissionPreferences,
  getHlinkConfig,
  updateHlinkConfig,
  inviteDelegate,
  acceptInvitation,
  listDelegates,
  updateDelegatePermissions,
  revokeDelegate,
  listPhysiciansForDelegate,
  switchPhysicianContext,
  getProviderContext,
  getBaForClaim,
  getWcbConfigForFormOrThrow,
  type ProviderServiceDeps,
} from './provider.service.js';

// ---------------------------------------------------------------------------
// Handler dependencies
// ---------------------------------------------------------------------------

export interface ProviderHandlerDeps {
  serviceDeps: ProviderServiceDeps;
}

// ---------------------------------------------------------------------------
// Helper: extract providerId from auth context
// ---------------------------------------------------------------------------

function getProviderId(request: FastifyRequest): string {
  const ctx = request.authContext;
  // Delegates use their active physician context
  if (ctx.role?.toUpperCase() === 'DELEGATE' && (ctx as any).delegateContext) {
    return (ctx as any).delegateContext.physicianProviderId;
  }
  // Physicians: userId === providerId (1:1 mapping)
  return ctx.userId;
}

// ---------------------------------------------------------------------------
// Handler factory
// ---------------------------------------------------------------------------

export function createProviderHandlers(deps: ProviderHandlerDeps) {
  const { serviceDeps } = deps;

  // =========================================================================
  // Provider Profile Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me
  // -------------------------------------------------------------------------

  async function getProfileHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const profile = await getProviderProfile(serviceDeps, providerId);
    return reply.code(200).send({ data: profile });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/providers/me
  // -------------------------------------------------------------------------

  async function updateProfileHandler(
    request: FastifyRequest<{ Body: UpdateProvider }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const body = request.body;

    const updated = await updateProviderProfile(
      serviceDeps,
      providerId,
      {
        firstName: body.first_name,
        lastName: body.last_name,
        middleName: body.middle_name,
        specialtyCode: body.specialty_code,
        specialtyDescription: body.specialty_description,
        subSpecialtyCode: body.sub_specialty_code,
        physicianType: body.physician_type,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({ data: updated });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me/onboarding-status
  // -------------------------------------------------------------------------

  async function onboardingStatusHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const status = await getOnboardingStatus(serviceDeps, providerId);
    return reply.code(200).send({ data: status });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/providers/me/complete-onboarding
  // -------------------------------------------------------------------------

  async function completeOnboardingHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const result = await completeOnboarding(serviceDeps, providerId);

    if (!result.success) {
      return reply.code(422).send({
        error: {
          code: 'BUSINESS_RULE_VIOLATION',
          message: 'Onboarding requirements not met',
          details: { missingFields: result.missingFields },
        },
      });
    }

    return reply.code(200).send({ data: { message: 'Onboarding completed', provider: result.provider } });
  }

  // =========================================================================
  // Business Arrangement Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me/bas
  // -------------------------------------------------------------------------

  async function listBasHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const bas = await listBas(serviceDeps, providerId);
    return reply.code(200).send({ data: bas });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/providers/me/bas
  // -------------------------------------------------------------------------

  async function addBaHandler(
    request: FastifyRequest<{ Body: CreateBa }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const body = request.body;

    const ba = await addBa(
      serviceDeps,
      providerId,
      {
        baNumber: body.ba_number,
        baType: body.ba_type,
        isPrimary: body.is_primary,
        effectiveDate: body.effective_date,
      },
      request.authContext.userId,
    );

    return reply.code(201).send({ data: ba });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/providers/me/bas/:id
  // -------------------------------------------------------------------------

  async function updateBaHandler(
    request: FastifyRequest<{ Body: UpdateBa; Params: BaIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { id } = request.params;
    const body = request.body;

    const updated = await updateBa(
      serviceDeps,
      providerId,
      id,
      {
        status: body.status,
        effectiveDate: body.effective_date,
        endDate: body.end_date,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({ data: updated });
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/providers/me/bas/:id
  // -------------------------------------------------------------------------

  async function deactivateBaHandler(
    request: FastifyRequest<{ Params: BaIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { id } = request.params;

    await deactivateBa(serviceDeps, providerId, id, request.authContext.userId);

    return reply.code(204).send();
  }

  // =========================================================================
  // Practice Location Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me/locations
  // -------------------------------------------------------------------------

  async function listLocationsHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const locations = await listLocations(serviceDeps, providerId);
    return reply.code(200).send({ data: locations });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/providers/me/locations
  // -------------------------------------------------------------------------

  async function addLocationHandler(
    request: FastifyRequest<{ Body: CreateLocation }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const body = request.body;

    const location = await addLocation(
      serviceDeps,
      providerId,
      {
        name: body.name,
        functionalCentre: body.functional_centre,
        facilityNumber: body.facility_number,
        addressLine1: body.address_line_1,
        addressLine2: body.address_line_2,
        city: body.city,
        province: body.province,
        postalCode: body.postal_code,
        communityCode: body.community_code,
      },
      request.authContext.userId,
    );

    return reply.code(201).send({ data: location });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/providers/me/locations/:id
  // -------------------------------------------------------------------------

  async function updateLocationHandler(
    request: FastifyRequest<{ Body: UpdateLocation; Params: LocationIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { id } = request.params;
    const body = request.body;

    const updated = await updateLocation(
      serviceDeps,
      providerId,
      id,
      {
        name: body.name,
        functionalCentre: body.functional_centre,
        facilityNumber: body.facility_number,
        addressLine1: body.address_line_1,
        addressLine2: body.address_line_2,
        city: body.city,
        province: body.province,
        postalCode: body.postal_code,
        communityCode: body.community_code,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({ data: updated });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/providers/me/locations/:id/set-default
  // -------------------------------------------------------------------------

  async function setDefaultLocationHandler(
    request: FastifyRequest<{ Params: LocationIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { id } = request.params;

    const location = await setDefaultLocation(
      serviceDeps,
      providerId,
      id,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: location });
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/providers/me/locations/:id
  // -------------------------------------------------------------------------

  async function deactivateLocationHandler(
    request: FastifyRequest<{ Params: LocationIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { id } = request.params;

    await deactivateLocation(serviceDeps, providerId, id, request.authContext.userId);

    return reply.code(204).send();
  }

  // =========================================================================
  // WCB Configuration Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me/wcb
  // -------------------------------------------------------------------------

  async function listWcbConfigsHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const configs = await listWcbConfigs(serviceDeps, providerId);
    return reply.code(200).send({ data: configs });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/providers/me/wcb
  // -------------------------------------------------------------------------

  async function addWcbConfigHandler(
    request: FastifyRequest<{ Body: CreateWcbConfig }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const body = request.body;

    const config = await addWcbConfig(
      serviceDeps,
      providerId,
      {
        contractId: body.contract_id,
        roleCode: body.role_code,
        skillCode: body.skill_code,
        isDefault: body.is_default,
      },
      request.authContext.userId,
    );

    return reply.code(201).send({ data: config });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/providers/me/wcb/:id
  // -------------------------------------------------------------------------

  async function updateWcbConfigHandler(
    request: FastifyRequest<{ Body: UpdateWcbConfig; Params: WcbConfigIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { id } = request.params;
    const body = request.body;

    const updated = await updateWcbConfig(
      serviceDeps,
      providerId,
      id,
      {
        skillCode: body.skill_code,
        isDefault: body.is_default,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({ data: updated });
  }

  // -------------------------------------------------------------------------
  // DELETE /api/v1/providers/me/wcb/:id
  // -------------------------------------------------------------------------

  async function removeWcbConfigHandler(
    request: FastifyRequest<{ Params: WcbConfigIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { id } = request.params;

    await removeWcbConfig(serviceDeps, providerId, id, request.authContext.userId);

    return reply.code(204).send();
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me/wcb/form-permissions
  // -------------------------------------------------------------------------

  async function formPermissionsHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const forms = await getFormPermissions(serviceDeps, providerId);
    return reply.code(200).send({ data: forms });
  }

  // =========================================================================
  // Submission Preferences Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me/submission-preferences
  // -------------------------------------------------------------------------

  async function getPreferencesHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const prefs = await getSubmissionPreferences(serviceDeps, providerId);
    return reply.code(200).send({ data: prefs });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/providers/me/submission-preferences
  // -------------------------------------------------------------------------

  async function updatePreferencesHandler(
    request: FastifyRequest<{ Body: UpdateSubmissionPreferences }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const body = request.body;

    const updated = await updateSubmissionPreferences(
      serviceDeps,
      providerId,
      {
        ahcipSubmissionMode: body.ahcip_submission_mode,
        wcbSubmissionMode: body.wcb_submission_mode,
        batchReviewReminder: body.batch_review_reminder,
        deadlineReminderDays: body.deadline_reminder_days,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({ data: updated });
  }

  // =========================================================================
  // H-Link Configuration Handlers
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me/hlink
  // -------------------------------------------------------------------------

  async function getHlinkConfigHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const config = await getHlinkConfig(serviceDeps, providerId);
    return reply.code(200).send({ data: config });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/providers/me/hlink
  // -------------------------------------------------------------------------

  async function updateHlinkConfigHandler(
    request: FastifyRequest<{ Body: UpdateHlinkConfig }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const body = request.body;

    const updated = await updateHlinkConfig(
      serviceDeps,
      providerId,
      {
        submitterPrefix: body.submitter_prefix,
        accreditationStatus: body.accreditation_status,
      },
      request.authContext.userId,
    );

    return reply.code(200).send({ data: updated });
  }

  // =========================================================================
  // Delegate Management Handlers (physician role)
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/providers/me/delegates
  // -------------------------------------------------------------------------

  async function listDelegatesHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const delegates = await listDelegates(serviceDeps, providerId);
    return reply.code(200).send({ data: delegates });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/providers/me/delegates/invite
  // -------------------------------------------------------------------------

  async function inviteDelegateHandler(
    request: FastifyRequest<{ Body: InviteDelegate }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const body = request.body;

    const result = await inviteDelegate(
      serviceDeps,
      providerId,
      body.email,
      body.permissions,
      request.authContext.userId,
    );

    return reply.code(201).send({
      data: {
        relationshipId: result.relationship.relationshipId,
        status: result.relationship.status,
      },
    });
  }

  // -------------------------------------------------------------------------
  // PUT /api/v1/providers/me/delegates/:rel_id/permissions
  // -------------------------------------------------------------------------

  async function updateDelegatePermissionsHandler(
    request: FastifyRequest<{ Body: UpdateDelegatePermissions; Params: DelegateRelIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { rel_id } = request.params;

    const updated = await updateDelegatePermissions(
      serviceDeps,
      providerId,
      rel_id,
      request.body.permissions,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: updated });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/providers/me/delegates/:rel_id/revoke
  // -------------------------------------------------------------------------

  async function revokeDelegateHandler(
    request: FastifyRequest<{ Params: DelegateRelIdParam }>,
    reply: FastifyReply,
  ) {
    const providerId = getProviderId(request);
    const { rel_id } = request.params;

    const revoked = await revokeDelegate(
      serviceDeps,
      providerId,
      rel_id,
      request.authContext.userId,
    );

    return reply.code(200).send({ data: revoked });
  }

  // =========================================================================
  // Delegate Self-Service Handlers (delegate role)
  // =========================================================================

  // -------------------------------------------------------------------------
  // GET /api/v1/delegates/me/physicians
  // -------------------------------------------------------------------------

  async function listPhysiciansHandler(
    request: FastifyRequest,
    reply: FastifyReply,
  ) {
    const delegateUserId = request.authContext.userId;
    const physicians = await listPhysiciansForDelegate(serviceDeps, delegateUserId);
    return reply.code(200).send({ data: physicians });
  }

  // -------------------------------------------------------------------------
  // POST /api/v1/delegates/me/switch-context/:provider_id
  // -------------------------------------------------------------------------

  async function switchContextHandler(
    request: FastifyRequest<{ Params: SwitchContextParam }>,
    reply: FastifyReply,
  ) {
    const delegateUserId = request.authContext.userId;
    const { provider_id } = request.params;

    const context = await switchPhysicianContext(
      serviceDeps,
      delegateUserId,
      provider_id,
    );

    return reply.code(200).send({ data: context });
  }

  // =========================================================================
  // Invitation Acceptance Handler (unauthenticated — token-based)
  // =========================================================================

  // -------------------------------------------------------------------------
  // POST /api/v1/delegates/invitations/:token/accept
  // -------------------------------------------------------------------------

  async function acceptInvitationHandler(
    request: FastifyRequest<{ Params: { token: string }; Body: AcceptInvitation }>,
    reply: FastifyReply,
  ) {
    // The path :token is the relationship ID (identifies the invitation).
    // The body token is the raw secret from the invitation email.
    const relationshipId = request.params.token;
    const rawToken = request.body.token;

    // For unauthenticated acceptance, delegateUserId is not yet known.
    // Pass a placeholder — the service resolves the actual delegate identity
    // when the invitation is linked to a user account on first login.
    const delegateUserId = 'anonymous';

    const accepted = await acceptInvitation(
      serviceDeps,
      rawToken,
      delegateUserId,
      relationshipId,
    );

    return reply.code(200).send({
      data: {
        relationshipId: accepted.relationshipId,
        status: accepted.status,
      },
    });
  }

  return {
    // Profile
    getProfileHandler,
    updateProfileHandler,
    onboardingStatusHandler,
    completeOnboardingHandler,
    // Business Arrangements
    listBasHandler,
    addBaHandler,
    updateBaHandler,
    deactivateBaHandler,
    // Locations
    listLocationsHandler,
    addLocationHandler,
    updateLocationHandler,
    setDefaultLocationHandler,
    deactivateLocationHandler,
    // WCB Configuration
    listWcbConfigsHandler,
    addWcbConfigHandler,
    updateWcbConfigHandler,
    removeWcbConfigHandler,
    formPermissionsHandler,
    // Submission Preferences
    getPreferencesHandler,
    updatePreferencesHandler,
    // H-Link Configuration
    getHlinkConfigHandler,
    updateHlinkConfigHandler,
    // Delegate Management (physician)
    listDelegatesHandler,
    inviteDelegateHandler,
    updateDelegatePermissionsHandler,
    revokeDelegateHandler,
    // Delegate Self-Service (delegate)
    listPhysiciansHandler,
    switchContextHandler,
    // Invitation Acceptance (unauthenticated)
    acceptInvitationHandler,
  };
}

// ---------------------------------------------------------------------------
// Internal API Key Verification (constant-time comparison)
// ---------------------------------------------------------------------------

/**
 * Verify the X-Internal-API-Key header against process.env.INTERNAL_API_KEY.
 * Uses constant-time comparison to prevent timing attacks.
 */
export function verifyInternalApiKey(
  request: FastifyRequest,
  reply: FastifyReply,
): boolean {
  const apiKey = request.headers['x-internal-api-key'] as string | undefined;
  const expectedKey = process.env.INTERNAL_API_KEY;

  if (!apiKey || !expectedKey) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  const keyBuffer = Buffer.from(apiKey);
  const expectedBuffer = Buffer.from(expectedKey);

  if (keyBuffer.length !== expectedBuffer.length) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  if (!timingSafeEqual(keyBuffer, expectedBuffer)) {
    reply.code(401).send({
      error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
    });
    return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// Internal Provider Context Handlers (service-to-service, API key auth)
// ---------------------------------------------------------------------------

export interface InternalProviderHandlerDeps {
  serviceDeps: ProviderServiceDeps;
}

export function createInternalProviderHandlers(deps: InternalProviderHandlerDeps) {
  const { serviceDeps } = deps;

  // -------------------------------------------------------------------------
  // GET /api/v1/internal/providers/:id/claim-context
  // -------------------------------------------------------------------------

  async function claimContextHandler(
    request: FastifyRequest<{ Params: ProviderIdParam }>,
    reply: FastifyReply,
  ) {
    if (!verifyInternalApiKey(request, reply)) return;

    const { id } = request.params;
    const context = await getProviderContext(serviceDeps, id);

    if (!context) {
      return reply.code(404).send({
        error: { code: 'NOT_FOUND', message: 'Resource not found' },
      });
    }

    return reply.code(200).send({ data: context });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/internal/providers/:id/ba-for-claim
  // -------------------------------------------------------------------------

  async function baForClaimHandler(
    request: FastifyRequest<{ Params: ProviderIdParam; Querystring: BaForClaimQuery }>,
    reply: FastifyReply,
  ) {
    if (!verifyInternalApiKey(request, reply)) return;

    const { id } = request.params;
    const { claim_type, hsc_code } = request.query;

    const result = await getBaForClaim(
      serviceDeps,
      id,
      claim_type,
      hsc_code,
    );

    return reply.code(200).send({ data: result });
  }

  // -------------------------------------------------------------------------
  // GET /api/v1/internal/providers/:id/wcb-config-for-form
  // -------------------------------------------------------------------------

  async function wcbConfigForFormHandler(
    request: FastifyRequest<{ Params: ProviderIdParam; Querystring: WcbConfigForFormQuery }>,
    reply: FastifyReply,
  ) {
    if (!verifyInternalApiKey(request, reply)) return;

    const { id } = request.params;
    const { form_id } = request.query;

    const config = await getWcbConfigForFormOrThrow(serviceDeps, id, form_id);

    return reply.code(200).send({ data: config });
  }

  return {
    claimContextHandler,
    baForClaimHandler,
    wcbConfigForFormHandler,
  };
}
