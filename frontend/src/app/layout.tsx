import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Argus Code — Multi-Agent Developer Platform",
  description: "Autonomous multi-agent AST static analysis, security auditing, and automated Git diff generation.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body
        suppressHydrationWarning
        className="antialiased bg-[#0a0c10] text-slate-200 h-screen w-screen flex flex-col"
      >
        {children}
      </body>
    </html>
  );
}
