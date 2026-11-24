"use client";

import ReactMarkdown, { type Components } from "react-markdown";

const LINK_ALLOWLIST = [
  "nvd.nist.gov",
  "csrc.nist.gov",
  "nvlpubs.nist.gov",
  "datatracker.ietf.org",
];

function isAllowedLink(href: string): boolean {
  try {
    const url = new URL(href);
    if (url.protocol !== "https:") return false;
    return LINK_ALLOWLIST.some(
      (domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`),
    );
  } catch {
    return false;
  }
}

function urlTransform(url: string): string {
  return isAllowedLink(url) ? url : "";
}

const components: Components = {
  h1: (props) => <h1 className="mb-3 mt-5 text-xl font-bold first:mt-0" {...props} />,
  h2: (props) => <h2 className="mb-2 mt-5 text-lg font-semibold first:mt-0" {...props} />,
  h3: (props) => <h3 className="mb-2 mt-4 text-base font-semibold first:mt-0" {...props} />,
  h4: (props) => <h4 className="mb-1.5 mt-3 text-sm font-semibold first:mt-0" {...props} />,
  p: (props) => <p className="mb-3 leading-relaxed last:mb-0" {...props} />,
  ul: (props) => <ul className="mb-3 list-disc space-y-1 pl-5 last:mb-0" {...props} />,
  ol: (props) => <ol className="mb-3 list-decimal space-y-1 pl-5 last:mb-0" {...props} />,
  li: (props) => <li className="pl-1 leading-relaxed" {...props} />,
  strong: (props) => <strong className="font-semibold text-foreground" {...props} />,
  em: (props) => <em className="italic" {...props} />,
  blockquote: (props) => (
    <blockquote className="mb-3 border-l-2 border-border pl-3 italic text-muted-foreground" {...props} />
  ),
  code: (props) => (
    <code className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em]" {...props} />
  ),
  pre: (props) => (
    <pre className="mb-3 overflow-x-auto rounded-md border bg-muted p-3 text-xs [&_code]:bg-transparent [&_code]:p-0" {...props} />
  ),
  hr: (props) => <hr className="my-4 border-border" {...props} />,
  table: (props) => (
    <div className="mb-3 overflow-x-auto">
      <table className="w-full border-collapse text-sm" {...props} />
    </div>
  ),
  th: (props) => <th className="border border-border px-2 py-1 text-left font-semibold" {...props} />,
  td: (props) => <td className="border border-border px-2 py-1" {...props} />,
  a: ({ href, children, ...props }) =>
    href && isAllowedLink(href) ? (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="text-primary underline underline-offset-2"
        {...props}
      >
        {children}
      </a>
    ) : (
      <span {...props}>{children}</span>
    ),
};

export function SafeMarkdown({
  text,
  className,
}: {
  text: string;
  className?: string;
}) {
  return (
    <div className={`text-sm text-foreground ${className ?? ""}`}>
      <ReactMarkdown
        components={components}
        disallowedElements={["img", "script", "iframe"]}
        unwrapDisallowed
        urlTransform={urlTransform}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
