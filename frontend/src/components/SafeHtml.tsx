"use client";

/**
 * SafeHtml — Renders untrusted HTML/text safely via DOMPurify.
 *
 * Use this for any user-controlled or tool-generated content that may contain
 * HTML, script tags, or other injection vectors. Covers:
 *   - Agent raw_command output in Health Feed
 *   - Finding detail/value fields
 *   - Chat message content
 *   - Any field populated by external tool stdout
 *
 * DOMPurify strips all dangerous tags/attributes while preserving safe formatting.
 */

import { useMemo } from "react";
import DOMPurify from "dompurify";

interface SafeHtmlProps {
  /** Raw HTML or text to sanitize and render */
  html: string;
  /** HTML element to render as (default: span) */
  as?: keyof JSX.IntrinsicElements;
  /** Additional CSS classes */
  className?: string;
}

export default function SafeHtml({ html, as: Tag = "span", className }: SafeHtmlProps) {
  const clean = useMemo(() => {
    if (typeof window === "undefined") {
      // SSR fallback — strip all HTML tags
      return html.replace(/<[^>]*>/g, "");
    }
    return DOMPurify.sanitize(html, {
      ALLOWED_TAGS: ["b", "i", "em", "strong", "code", "pre", "br", "span", "a"],
      ALLOWED_ATTR: ["class", "href", "target", "rel"],
      ADD_ATTR: ["target"], // allow target="_blank" on links
    });
  }, [html]);

  return <Tag className={className} dangerouslySetInnerHTML={{ __html: clean }} />;
}

/**
 * sanitizeText — For contexts where you need plain text only (no HTML at all).
 * Use in attributes, titles, aria-labels, etc.
 */
export function sanitizeText(text: string): string {
  return text.replace(/<[^>]*>/g, "").replace(/[<>"'&]/g, (c) => {
    const map: Record<string, string> = { "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "&": "&amp;" };
    return map[c] || c;
  });
}
