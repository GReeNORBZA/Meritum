import { useState, useRef, useCallback } from 'preact/hooks';

const tabs = [
  {
    id: 'emr-import',
    label: 'EMR import',
    heading: 'If you use an EMR: import your encounters',
    content: [
      'Export your encounters from your EMR system and import the file into Meritum. The platform reads the encounter data, maps it to AHCIP service codes, and queues the claims for rules checking. You review anything that needs attention; clean claims are cleared for the next Thursday submission.',
      'At launch, EMR integration works through file exports from systems like Med Access, Wolf Medical, and Accuro. You export from your EMR and import into Meritum. File import is a significant improvement over manual re-entry, and direct API integration with EMR vendors is on the roadmap.',
    ],
  },
  {
    id: 'mobile-entry',
    label: 'Mobile entry',
    heading: 'If you\'re on shift: mobile claim entry',
    content: [
      'For ED shifts, after-hours hospital work, and anywhere else you need to log a claim at the point of care, Meritum\'s mobile entry captures the patient, the service codes, and the timestamps on your phone. The claim is queued the moment you enter it. No paper billing sheets, no pocket full of notes to transcribe later, and no gap between the care and the record.',
      'The after-hours time premium (03.01AA) is calculated automatically from your documented start and end times: the platform applies the correct time-period modifier so the premium pays out at the right rate, whether you worked a weekday evening or an overnight.',
    ],
  },
  {
    id: 'manual-entry',
    label: 'Manual entry',
    heading: 'If you prefer to enter claims directly: manual entry',
    content: [
      'Meritum\'s claim entry form is designed for speed. Select your patient, your service codes, and your location; the rules engine validates the claim as you build it, flagging issues before you save. For physicians who are used to entering their own claims, this is the familiar workflow with a rules layer running underneath it.',
    ],
  },
] as const;

export default function DailyWorkflow() {
  const [activeTab, setActiveTab] = useState(0);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      let nextIndex: number | null = null;

      switch (e.key) {
        case 'ArrowRight':
          nextIndex = (activeTab + 1) % tabs.length;
          break;
        case 'ArrowLeft':
          nextIndex = (activeTab - 1 + tabs.length) % tabs.length;
          break;
        case 'Home':
          nextIndex = 0;
          break;
        case 'End':
          nextIndex = tabs.length - 1;
          break;
        default:
          return;
      }

      e.preventDefault();
      setActiveTab(nextIndex);
      tabRefs.current[nextIndex]?.focus();
    },
    [activeTab],
  );

  return (
    <div class="mx-auto max-w-3xl">
      <div
        role="tablist"
        aria-label="Claim entry methods"
        class="flex gap-1 rounded-lg bg-white p-1"
        onKeyDown={handleKeyDown}
      >
        {tabs.map((tab, i) => (
          <button
            key={tab.id}
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={activeTab === i}
            aria-controls={`panel-${tab.id}`}
            tabIndex={activeTab === i ? 0 : -1}
            ref={(el) => {
              tabRefs.current[i] = el;
            }}
            onClick={() => setActiveTab(i)}
            class={`flex-1 rounded-md px-4 py-2.5 text-sm font-medium transition-colors ${
              activeTab === i
                ? 'bg-[#1B2A4A] text-white'
                : 'text-[#5A5A6E] hover:text-[#1A1A2E]'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div class="mt-8">
        {tabs.map((tab, i) => (
          <div
            key={tab.id}
            id={`panel-${tab.id}`}
            role="tabpanel"
            aria-labelledby={`tab-${tab.id}`}
            hidden={activeTab !== i}
            tabIndex={0}
          >
            {activeTab === i && (
              <div class="space-y-4">
                <h3 class="font-bold text-lg text-[#1B2A4A] font-['Satoshi',sans-serif]">
                  {tab.heading}
                </h3>
                {tab.content.map((paragraph, j) => (
                  <p key={j} class="text-base leading-relaxed text-[#1A1A2E]">
                    {paragraph}
                  </p>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
