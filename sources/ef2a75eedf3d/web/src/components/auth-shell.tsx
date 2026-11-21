import type { ReactNode } from "react";

import { VulneticBrand } from "@/components/vulnetic-brand";

export function AuthShell({ children }: { children: ReactNode }) {
  return (
    <div className="auth-shell min-h-dvh lg:grid lg:grid-cols-[minmax(20rem,1fr)_2fr]">
      <aside className="hidden flex-col justify-between bg-[#171c24] p-12 text-[#f5f7fc] lg:flex xl:p-14">
        <VulneticBrand className="text-[#f5f7fc] [&_svg_path]:stroke-[#171c24]" />
        <div className="max-w-sm py-16">
          <h2 className="text-4xl leading-tight font-medium tracking-tight text-balance">From scope to evidence.</h2>
          <p className="mt-6 text-base leading-relaxed text-[#c7d0e0]">
            Your workspace for remote security testing, execution review and reproducible results.
          </p>
        </div>
        <p className="text-xs text-[#c7d0e0]">Vulnetic security workspace</p>
      </aside>
      <main className="flex min-h-dvh items-center justify-center bg-card px-6 py-12 sm:px-10">
        <div className="w-full max-w-[25rem]">
          <VulneticBrand className="mb-12 lg:hidden" />
          {children}
          <p className="mt-8 text-center text-xs text-muted-foreground">
            <a href="/source/" className="underline-offset-4 hover:underline focus-visible:underline">
              Source &amp; credits · AGPL-3.0
            </a>
          </p>
        </div>
      </main>
    </div>
  );
}
