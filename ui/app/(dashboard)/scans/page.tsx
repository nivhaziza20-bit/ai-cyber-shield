import { Header } from "@/components/layout/header";
import { ScanFeed } from "@/components/scan-feed/scan-feed";
import { AttackChainGraph } from "@/components/attack-chain/attack-chain-graph";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata = { title: "Scans" };

export default function ScansPage() {
  return (
    <>
      <Header title="Scans" subtitle="Live scan feed with real-time findings" />
      <div className="flex-1 overflow-auto p-6 space-y-6 scrollbar-thin">
        <ScanFeedDemo />
        <Card>
          <CardHeader>
            <CardTitle>Attack Chain Visualization</CardTitle>
          </CardHeader>
          <CardContent>
            <AttackChainGraph />
          </CardContent>
        </Card>
      </div>
    </>
  );
}

// Client wrapper — renders the SSE feed with demo scan ID
function ScanFeedDemo() {
  "use client";
  // In production this comes from route params / URL query
  const DEMO_SCAN_ID = "scan-live-001";

  return (
    <div className="h-[440px]">
      <ScanFeedClient scanId={DEMO_SCAN_ID} />
    </div>
  );
}

// Separate client component to keep page as server component
import { ScanFeedClient } from "./scan-feed-client";
