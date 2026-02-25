import { PcpcmPaymentStatus } from '@meritum/shared/constants/provider.constants.js';
import { BusinessRuleError, NotFoundError } from '../../lib/errors.js';
import { type PcpcmPaymentRepository } from './pcpcm-payment.repository.js';

// ---------------------------------------------------------------------------
// Dependency injection type
// ---------------------------------------------------------------------------

export type PcpcmServiceDeps = {
  pcpcmPaymentRepo: PcpcmPaymentRepository;
};

// ---------------------------------------------------------------------------
// Reconciliation tolerance: $0.01
// ---------------------------------------------------------------------------

const RECONCILIATION_TOLERANCE = 0.01;

// ---------------------------------------------------------------------------
// recordPcpcmPayment
// ---------------------------------------------------------------------------

/**
 * Record a new PCPCM capitation payment.
 * - Validates enrolment exists for the given provider.
 * - Sets status to EXPECTED if only expectedAmount given,
 *   RECEIVED if actualAmount is provided.
 */
export async function recordPcpcmPayment(
  deps: PcpcmServiceDeps,
  providerId: string,
  paymentData: {
    enrolmentId: string;
    paymentPeriodStart: string;
    paymentPeriodEnd: string;
    expectedAmount?: number;
    actualAmount?: number;
    panelSizeAtPayment?: number;
    notes?: string;
  },
  _actorId: string,
) {
  const { pcpcmPaymentRepo } = deps;

  // Validate enrolment exists and belongs to this provider
  const enrolment = await pcpcmPaymentRepo.findEnrolmentByIdAndProvider(
    paymentData.enrolmentId,
    providerId,
  );
  if (!enrolment) {
    throw new NotFoundError('PCPCM enrolment');
  }

  // Determine initial status
  const status = paymentData.actualAmount !== undefined
    ? PcpcmPaymentStatus.RECEIVED
    : PcpcmPaymentStatus.EXPECTED;

  const record = await pcpcmPaymentRepo.createPcpcmPayment({
    providerId,
    enrolmentId: paymentData.enrolmentId,
    paymentPeriodStart: paymentData.paymentPeriodStart,
    paymentPeriodEnd: paymentData.paymentPeriodEnd,
    expectedAmount: paymentData.expectedAmount !== undefined
      ? String(paymentData.expectedAmount)
      : undefined,
    actualAmount: paymentData.actualAmount !== undefined
      ? String(paymentData.actualAmount)
      : undefined,
    panelSizeAtPayment: paymentData.panelSizeAtPayment,
    notes: paymentData.notes,
    status,
  });

  return record;
}

// ---------------------------------------------------------------------------
// reconcilePcpcmPayments
// ---------------------------------------------------------------------------

/**
 * Reconcile all unreconciled PCPCM payments for a provider.
 * For each payment that has both expectedAmount and actualAmount:
 *   - If they match within $0.01 tolerance -> RECONCILED
 *   - If they differ -> DISCREPANCY
 * Payments missing either amount are skipped.
 *
 * Returns summary: { reconciled, discrepancies, details }
 */
export async function reconcilePcpcmPayments(
  deps: PcpcmServiceDeps,
  providerId: string,
  _actorId: string,
) {
  const { pcpcmPaymentRepo } = deps;

  const unreconciledPayments = await pcpcmPaymentRepo.findUnreconciledPayments(providerId);

  let reconciled = 0;
  let discrepancies = 0;
  const details: Array<{
    paymentId: string;
    status: string;
    expectedAmount: string | null;
    actualAmount: string | null;
    difference?: number;
  }> = [];

  const now = new Date();

  for (const payment of unreconciledPayments) {
    const expected = payment.expectedAmount;
    const actual = payment.actualAmount;

    // Skip payments that don't have both amounts
    if (expected == null || actual == null) {
      continue;
    }

    const expectedNum = parseFloat(String(expected));
    const actualNum = parseFloat(String(actual));
    const difference = Math.abs(expectedNum - actualNum);

    if (difference <= RECONCILIATION_TOLERANCE) {
      // Match within tolerance
      await pcpcmPaymentRepo.updatePaymentStatus(
        payment.paymentId,
        providerId,
        PcpcmPaymentStatus.RECONCILED,
        now,
      );
      reconciled++;
      details.push({
        paymentId: payment.paymentId,
        status: PcpcmPaymentStatus.RECONCILED,
        expectedAmount: String(expected),
        actualAmount: String(actual),
      });
    } else {
      // Discrepancy
      const note = `Discrepancy: expected ${expectedNum.toFixed(2)}, actual ${actualNum.toFixed(2)}, difference ${difference.toFixed(2)}`;
      await pcpcmPaymentRepo.updatePaymentStatus(
        payment.paymentId,
        providerId,
        PcpcmPaymentStatus.DISCREPANCY,
        now,
        note,
      );
      discrepancies++;
      details.push({
        paymentId: payment.paymentId,
        status: PcpcmPaymentStatus.DISCREPANCY,
        expectedAmount: String(expected),
        actualAmount: String(actual),
        difference,
      });
    }
  }

  return { reconciled, discrepancies, details };
}

// ---------------------------------------------------------------------------
// getPcpcmPaymentHistory
// ---------------------------------------------------------------------------

/**
 * Get paginated PCPCM payment history for a provider.
 * Supports optional filters: status, periodStart, periodEnd.
 */
export async function getPcpcmPaymentHistory(
  deps: PcpcmServiceDeps,
  providerId: string,
  filters?: {
    status?: string;
    periodStart?: string;
    periodEnd?: string;
    page?: number;
    pageSize?: number;
  },
) {
  const { pcpcmPaymentRepo } = deps;

  const page = filters?.page ?? 1;
  const pageSize = filters?.pageSize ?? 20;
  const offset = (page - 1) * pageSize;

  const result = await pcpcmPaymentRepo.listPcpcmPaymentsForProvider(providerId, {
    status: filters?.status,
    periodStart: filters?.periodStart,
    periodEnd: filters?.periodEnd,
    limit: pageSize,
    offset,
  });

  return {
    data: result.data,
    pagination: {
      total: result.total,
      page,
      pageSize,
      hasMore: offset + result.data.length < result.total,
    },
  };
}

// ---------------------------------------------------------------------------
// updatePanelSize
// ---------------------------------------------------------------------------

/**
 * Update the panel size on a PCPCM enrolment.
 * Validates:
 *  - panelSize is a positive integer
 *  - enrolment belongs to the provider
 */
export async function updatePanelSize(
  deps: PcpcmServiceDeps,
  providerId: string,
  enrolmentId: string,
  panelSize: number,
  _actorId: string,
) {
  const { pcpcmPaymentRepo } = deps;

  // Validate positive integer
  if (!Number.isInteger(panelSize) || panelSize <= 0) {
    throw new BusinessRuleError('Panel size must be a positive integer');
  }

  // Validate enrolment belongs to provider
  const enrolment = await pcpcmPaymentRepo.findEnrolmentByIdAndProvider(
    enrolmentId,
    providerId,
  );
  if (!enrolment) {
    throw new NotFoundError('PCPCM enrolment');
  }

  await pcpcmPaymentRepo.updatePanelSizeOnEnrolment(enrolmentId, providerId, panelSize);
}
