'use client';

import { useEffect, useRef, useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Camera, X, AlertTriangle } from 'lucide-react';

interface BarcodeScannerProps {
  onScan: (value: string) => void;
  onCancel: () => void;
}

export function BarcodeScanner({ onScan, onCancel }: BarcodeScannerProps) {
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [isSupported, setIsSupported] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [manualValue, setManualValue] = useState('');

  const stopCamera = useCallback(() => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((track) => track.stop());
      streamRef.current = null;
    }
  }, []);

  useEffect(() => {
    // Check for BarcodeDetector API support
    if (!('BarcodeDetector' in window)) {
      setIsSupported(false);
      return;
    }

    let cancelled = false;

    async function startScanning() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment' },
        });

        if (cancelled) {
          stream.getTracks().forEach((t) => t.stop());
          return;
        }

        streamRef.current = stream;

        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          await videoRef.current.play();
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const detector = new (window as any).BarcodeDetector({
          formats: ['code_128', 'code_39', 'ean_13', 'ean_8', 'qr_code'],
        });

        const detect = async () => {
          if (cancelled || !videoRef.current) return;

          try {
            const barcodes = await detector.detect(videoRef.current);
            if (barcodes.length > 0) {
              const value = barcodes[0].rawValue;
              if (value) {
                stopCamera();
                onScan(value);
                return;
              }
            }
          } catch {
            // Detection frame error, continue scanning
          }

          if (!cancelled) {
            requestAnimationFrame(detect);
          }
        };

        detect();
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error ? err.message : 'Failed to access camera'
          );
        }
      }
    }

    startScanning();

    return () => {
      cancelled = true;
      stopCamera();
    };
  }, [onScan, stopCamera]);

  const handleManualSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (manualValue.trim()) {
      stopCamera();
      onScan(manualValue.trim());
    }
  };

  // Fallback: Barcode Detection API not supported
  if (!isSupported) {
    return (
      <div className="flex flex-col items-center gap-4 p-6">
        <div className="flex items-center gap-2 text-amber-600">
          <AlertTriangle className="h-5 w-5" />
          <p className="text-sm font-medium">Barcode scanning not supported on this device</p>
        </div>
        <p className="text-xs text-muted-foreground text-center">
          Your browser does not support the Barcode Detection API. Please enter the value manually.
        </p>
        <form onSubmit={handleManualSubmit} className="flex w-full gap-2">
          <input
            type="text"
            value={manualValue}
            onChange={(e) => setManualValue(e.target.value)}
            placeholder="Enter barcode value..."
            className="flex-1 rounded-md border px-3 py-2 text-sm"
            autoFocus
          />
          <Button type="submit" size="sm" disabled={!manualValue.trim()}>
            Submit
          </Button>
        </form>
        <Button variant="ghost" size="sm" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    );
  }

  // Camera error fallback
  if (error) {
    return (
      <div className="flex flex-col items-center gap-4 p-6">
        <div className="flex items-center gap-2 text-destructive">
          <AlertTriangle className="h-5 w-5" />
          <p className="text-sm font-medium">Camera Error</p>
        </div>
        <p className="text-xs text-muted-foreground text-center">{error}</p>
        <form onSubmit={handleManualSubmit} className="flex w-full gap-2">
          <input
            type="text"
            value={manualValue}
            onChange={(e) => setManualValue(e.target.value)}
            placeholder="Enter barcode value manually..."
            className="flex-1 rounded-md border px-3 py-2 text-sm"
            autoFocus
          />
          <Button type="submit" size="sm" disabled={!manualValue.trim()}>
            Submit
          </Button>
        </form>
        <Button variant="ghost" size="sm" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    );
  }

  return (
    <div className="relative flex flex-col items-center">
      {/* Camera viewfinder */}
      <div className="relative w-full overflow-hidden rounded-lg bg-black">
        <video
          ref={videoRef}
          className="h-64 w-full object-cover"
          playsInline
          muted
        />
        {/* Scan area overlay */}
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div className="h-32 w-56 rounded-lg border-2 border-white/80 shadow-[0_0_0_9999px_rgba(0,0,0,0.4)]" />
        </div>
        {/* Scanning indicator */}
        <div className="absolute bottom-3 left-0 right-0 text-center">
          <span className="inline-flex items-center gap-1.5 rounded-full bg-black/60 px-3 py-1 text-xs text-white">
            <Camera className="h-3.5 w-3.5 animate-pulse" />
            Scanning...
          </span>
        </div>
      </div>

      {/* Cancel button */}
      <div className="mt-3 flex w-full justify-center">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            stopCamera();
            onCancel();
          }}
        >
          <X className="mr-1 h-4 w-4" />
          Cancel
        </Button>
      </div>
    </div>
  );
}
