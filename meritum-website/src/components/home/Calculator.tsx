import { useState } from 'preact/hooks';
import { pricingConfig } from '../../config/pricing';

function formatCAD(n: number): string {
  return `$${n.toLocaleString('en-CA')}`;
}

function TabA() {
  const [billings, setBillings] = useState(400000);
  const [pct, setPct] = useState(4);

  const agentCost = Math.round(billings * (pct / 100));
  const meritumCost = pricingConfig.earlyBird.active
    ? pricingConfig.earlyBird.annualRate
    : pricingConfig.standard.annualRate;
  const saving = agentCost - meritumCost;

  return (
    <div class="space-y-8">
      <div class="space-y-6">
        <div>
          <label class="block text-sm font-medium text-[#1A1A2E] mb-2" for="billings">
            Estimated annual AHCIP billings
          </label>
          <div class="flex items-center gap-4">
            <input
              type="range"
              id="billings"
              min={100000}
              max={2000000}
              step={10000}
              value={billings}
              onInput={(e) => setBillings(Number((e.target as HTMLInputElement).value))}
              class="flex-1 accent-[#C2973E]"
              aria-label="Estimated annual AHCIP billings"
            />
            <span class="w-32 text-right text-lg font-medium text-[#1B2A4A] font-['Satoshi',sans-serif]">
              {formatCAD(billings)}
            </span>
          </div>
        </div>

        <div>
          <label class="block text-sm font-medium text-[#1A1A2E] mb-2" for="agent-pct">
            Agent's percentage fee
          </label>
          <div class="flex items-center gap-4">
            <input
              type="range"
              id="agent-pct"
              min={3}
              max={5}
              step={0.5}
              value={pct}
              onInput={(e) => setPct(Number((e.target as HTMLInputElement).value))}
              class="flex-1 accent-[#C2973E]"
              aria-label="Agent's percentage fee"
            />
            <span class="w-32 text-right text-lg font-medium text-[#1B2A4A] font-['Satoshi',sans-serif]">
              {pct}%
            </span>
          </div>
        </div>
      </div>

      <div class="rounded-lg bg-white p-6 space-y-3">
        <div class="flex justify-between text-base">
          <span class="text-[#5A5A6E]">Annual agent cost</span>
          <span class="font-medium text-[#1A1A2E]">{formatCAD(agentCost)}/year</span>
        </div>
        <div class="flex justify-between text-base">
          <span class="text-[#5A5A6E]">Meritum annual cost</span>
          <span class="font-medium text-[#1A1A2E]">{formatCAD(meritumCost)}/year</span>
        </div>
        <hr class="border-[#F0EFEC]" />
        <div class="flex justify-between text-lg">
          <span class="font-medium text-[#1A1A2E]">Your annual saving</span>
          <span class="text-2xl font-bold text-[#C2973E] font-['Satoshi',sans-serif]">
            {saving > 0 ? formatCAD(saving) : '$0'}
          </span>
        </div>
      </div>

      <p class="text-sm text-[#5A5A6E] leading-relaxed">
        That's what you're paying for someone to submit claims you could submit yourself, with a platform that checks every governing rule before anything goes out.
      </p>
    </div>
  );
}

function TabB() {
  return (
    <div class="space-y-6 text-base leading-relaxed text-[#1A1A2E]">
      <p>
        Before a claim leaves Meritum, it's checked against every applicable governing rule in the AHCIP Schedule of Medical Benefits: your specialty, your patient's age, your service time, your location, your business arrangement type. Not guesswork. The rules themselves, applied automatically, before anything goes out.
      </p>

      <div>
        <h3 class="font-bold text-[#1B2A4A] font-['Satoshi',sans-serif] mb-2">After-hours time premium (03.01AA)</h3>
        <p class="text-sm text-[#1A1A2E] leading-relaxed">
          Code 03.01AA is an add-on time premium payable for patient care provided after hours. The rate depends on when you worked: weekday evenings and weekends pay $22.91 per unit, while nights (10pm to 7am) pay $45.77 per unit. Get the time-period modifier wrong, or miss the code entirely, and the premium doesn't pay out. Meritum calculates the applicable modifier automatically from your documented start and end times.
        </p>
      </div>

      <div>
        <h3 class="font-bold text-[#1B2A4A] font-['Satoshi',sans-serif] mb-2">Volume specialties and the scale problem</h3>
        <p class="text-sm text-[#1A1A2E] leading-relaxed">
          For high-volume specialties, the governing rules aren't complicated in isolation; they're complicated at scale. Radiology: an additional 30% benefit applies to eligible diagnostic imaging codes for patients 12 and under. Anesthesiology: billing combines base procedure units, time units, and qualifying circumstance modifiers. A missed qualifying circumstance on every case across a full OR schedule compounds quickly. Meritum checks governing rule eligibility on every claim before it goes out.
        </p>
      </div>

      <div>
        <h3 class="font-bold text-[#1B2A4A] font-['Satoshi',sans-serif] mb-2">RRNP</h3>
        <p class="text-sm text-[#1A1A2E] leading-relaxed">
          If you practice in an eligible rural or remote Alberta community, the Rural and Remote Northern Program adds an automatic premium to eligible services. Most billing software requires you to configure this yourself. Meritum calculates it automatically from your practice location and applies it to every eligible claim.
        </p>
      </div>

      <p class="text-sm text-[#5A5A6E]">
        These aren't obscure corner cases. They're governing rules that apply to common, everyday billing scenarios, and they're exactly the kind of thing that falls through the cracks when you're submitting after a full clinic or a night shift. Meritum doesn't rely on you knowing every rule. It checks them for you.
      </p>
    </div>
  );
}

export default function Calculator() {
  const [tab, setTab] = useState<'a' | 'b'>('a');

  return (
    <div class="mx-auto max-w-2xl">
      <h2 class="text-2xl font-bold text-[#1B2A4A] font-['Satoshi',sans-serif] lg:text-3xl">
        {tab === 'a'
          ? 'How much is your billing agent actually costing you?'
          : "Self-serve is the right call. The question is whether your software is checking the rules."}
      </h2>

      <div role="tablist" class="mt-8 flex gap-1 rounded-lg bg-white p-1">
        <button
          role="tab"
          aria-selected={tab === 'a'}
          aria-controls="tab-panel-a"
          id="tab-a"
          onClick={() => setTab('a')}
          class={`flex-1 rounded-md px-4 py-2.5 text-sm font-medium transition-colors ${
            tab === 'a'
              ? 'bg-[#1B2A4A] text-white'
              : 'text-[#5A5A6E] hover:text-[#1A1A2E]'
          }`}
        >
          Using a Billing Agent
        </button>
        <button
          role="tab"
          aria-selected={tab === 'b'}
          aria-controls="tab-panel-b"
          id="tab-b"
          onClick={() => setTab('b')}
          class={`flex-1 rounded-md px-4 py-2.5 text-sm font-medium transition-colors ${
            tab === 'b'
              ? 'bg-[#1B2A4A] text-white'
              : 'text-[#5A5A6E] hover:text-[#1A1A2E]'
          }`}
        >
          Using Self-Serve Software
        </button>
      </div>

      <div class="mt-8">
        <div
          id="tab-panel-a"
          role="tabpanel"
          aria-labelledby="tab-a"
          hidden={tab !== 'a'}
        >
          {tab === 'a' && <TabA />}
        </div>
        <div
          id="tab-panel-b"
          role="tabpanel"
          aria-labelledby="tab-b"
          hidden={tab !== 'b'}
        >
          {tab === 'b' && <TabB />}
        </div>
      </div>
    </div>
  );
}
