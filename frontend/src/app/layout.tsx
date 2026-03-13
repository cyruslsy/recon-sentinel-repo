import "@/styles/globals.css";
import { AuthProvider } from "@/lib/auth";

export const metadata = {
  title: "Recon Sentinel",
  description: "AI-Powered External Reconnaissance Platform",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-sentinel-bg text-sentinel-text min-h-screen">
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
