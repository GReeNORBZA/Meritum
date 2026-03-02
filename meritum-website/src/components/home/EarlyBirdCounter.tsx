import { useState, useEffect, useRef } from 'preact/hooks';
import { pricingConfig } from '../../config/pricing';

function useCountUp(target: number, duration = 1500): number {
  const [value, setValue] = useState(0);
  const startTime = useRef<number | null>(null);
  const rafId = useRef<number>(0);

  useEffect(() => {
    if (target <= 0) {
      setValue(0);
      return;
    }

    const animate = (timestamp: number) => {
      if (!startTime.current) startTime.current = timestamp;
      const elapsed = timestamp - startTime.current;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setValue(Math.round(eased * target));

      if (progress < 1) {
        rafId.current = requestAnimationFrame(animate);
      }
    };

    rafId.current = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(rafId.current);
  }, [target, duration]);

  return value;
}

export default function EarlyBirdCounter() {
  const [remaining, setRemaining] = useState(pricingConfig.earlyBird.spotsRemaining);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const fetchCount = async () => {
      try {
        const res = await fetch(pricingConfig.earlyBirdCountEndpoint);
        if (res.ok) {
          const json = await res.json();
          if (json?.data?.remaining != null) {
            setRemaining(json.data.remaining);
          }
        }
      } catch {
        // Keep default from config
      } finally {
        setLoaded(true);
      }
    };
    fetchCount();
  }, []);

  const displayValue = useCountUp(loaded ? remaining : 0);
  const total = pricingConfig.earlyBird.spotsTotal;
  const isLow = remaining < 20;

  if (!pricingConfig.earlyBird.active || remaining <= 0) {
    return null;
  }

  return (
    <div class="inline-flex items-baseline gap-2 text-white/90">
      <span
        class={`font-['Satoshi',sans-serif] font-bold tabular-nums ${
          isLow ? 'text-5xl' : 'text-4xl'
        }`}
      >
        {loaded ? displayValue : '--'}
      </span>
      <span class="text-lg text-white/70">
        of {total} early bird spots remaining
      </span>
    </div>
  );
}
