"use client";

import { useScanStream } from "@/hooks/use-scan-stream";
import { ScanFeed } from "@/components/scan-feed/scan-feed";

interface ScanFeedClientProps {
  scanId: string;
}

export function ScanFeedClient({ scanId }: ScanFeedClientProps) {
  const stream = useScanStream(scanId);

  return (
    <ScanFeed
      scanId     = {scanId}
      status     = {stream.status}
      findings   = {stream.findings}
      progress   = {stream.progress}
      error      = {stream.error}
      eventCount = {stream.eventCount}
      onStop     = {stream.stop}
    />
  );
}
