import type { ReactNode } from "react";

/** Small stroke icons (24px grid, currentColor). Decorative: the visible text carries the meaning. */
function Svg({ children }: { children: ReactNode }) {
  return (
    <svg className="icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {children}
    </svg>
  );
}

export const IconDashboard = () => <Svg><rect x="3" y="3" width="7.5" height="7.5" rx="1.5" /><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5" /><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5" /><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5" /></Svg>;
export const IconRegistries = () => <Svg><path d="M12 3 3 7.5 12 12l9-4.5L12 3Z" /><path d="m3 12 9 4.5 9-4.5" /><path d="m3 16.5 9 4.5 9-4.5" /></Svg>;
export const IconAudit = () => <Svg><path d="M7 3h8l4 4v14H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z" /><path d="M14 3v5h5" /><path d="M9 13h7M9 17h5" /></Svg>;
export const IconAccounts = () => <Svg><circle cx="9" cy="8" r="3.2" /><path d="M2.8 20c.4-3.4 3-5.5 6.2-5.5s5.8 2.1 6.2 5.5" /><circle cx="17" cy="9" r="2.5" /><path d="M16.5 14.6c2.6.2 4.4 2 4.7 4.8" /></Svg>;
export const IconShield = () => <Svg><path d="M12 3 4.5 6v5.5c0 4.5 3 8 7.5 9.5 4.5-1.5 7.5-5 7.5-9.5V6L12 3Z" /><path d="m9 12 2.2 2.2L15.5 10" /></Svg>;
export const IconUser = () => <Svg><circle cx="12" cy="8" r="3.6" /><path d="M4.5 20.5c.6-4 3.7-6.2 7.5-6.2s6.9 2.2 7.5 6.2" /></Svg>;
export const IconMenu = () => <Svg><path d="M4 7h16M4 12h16M4 17h16" /></Svg>;
export const IconClose = () => <Svg><path d="m6 6 12 12M18 6 6 18" /></Svg>;
export const IconChevronsLeft = () => <Svg><path d="m11 17-5-5 5-5M18 17l-5-5 5-5" /></Svg>;
export const IconChevronsRight = () => <Svg><path d="m13 17 5-5-5-5M6 17l5-5-5-5" /></Svg>;
export const IconSignOut = () => <Svg><path d="M9 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3" /><path d="m15 8 4 4-4 4M19 12H9" /></Svg>;
