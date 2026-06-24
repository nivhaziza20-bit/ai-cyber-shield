import { Header } from "@/components/layout/header";
import { AssetInventory } from "@/components/assets/asset-inventory";

export const metadata = { title: "Assets" };

export default function AssetsPage() {
  return (
    <>
      <Header title="Asset Inventory" subtitle="All discovered assets with risk scores and scan history" />
      <div className="flex-1 overflow-auto p-6 scrollbar-thin">
        <AssetInventory />
      </div>
    </>
  );
}
