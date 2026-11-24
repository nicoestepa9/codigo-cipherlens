"use client";

import { useState } from "react";
import { api, ApiError } from "@/services/apiClient";
import { PageHeader } from "@/components/shared/page-header";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlertTriangle, CircleCheck, CircleHelp } from "lucide-react";

interface Review {
  filename: string;
  modelVersion: string;
  datasetRevision: string;
  status: "possible_misuse" | "no_indication" | "not_evaluable" | "needs_review";
  misuseScore: number | null;
  scoreMeaning: string;
  limitations: string[];
  recommendation: string;
  findings?: { id: string; title: string; line: number | null; materialOriginLine?: number | null; evidence: string; value: string | number; recommendation: string; reference: string }[];
  observations?: { kind: string; value: string | number; line: number | null; evidence: string }[];
  unresolved?: { line: number | null; reason: string }[];
  contextNotes?: string[];
  ml?: { status: string; context?: { status: string; reason: string; score?: number; classification?: string; trainingSamples?: number; semanticTrainingSamples?: number; numericTrainingSamples?: number; validationSamples?: number; testSamples?: number; externalEvaluation?: { covered: number; metrics: { f1: number; recall: number } | null }; evaluation?: { test: { metrics: { precision: number; recall: number; f1: number; accuracy: number } | null; coverage: number; total: number } } }; supportedTransformations: string[]; predictions: { line: number | null; transformation: string; score: number; classification: string }[]; rsaPredictions?: { line: number | null; bits: number; score: number; classification: string }[]; rsaDomain?: number[]; rsaProvenance?: string; outOfScope: { line: number | null; transformation: string }[] };
}

function summarize(result: Review) {
  const classifierAlert = result.ml?.context?.classification === "possible_misuse"
    || result.ml?.predictions.some((item) => item.classification === "possible_misuse")
    || result.ml?.rsaPredictions?.some((item) => item.classification === "below_size_minimum");
  if (result.findings?.length) return {
    title: "Hay configuraciones que requieren atención",
    description: `${result.findings.length} ${result.findings.length === 1 ? "hallazgo en los controles aplicados. Revisá la recomendación siguiente." : "hallazgos en los controles aplicados. Revisá las recomendaciones siguientes."}`,
    tone: "border-red-500/40 bg-red-500/5", icon: AlertTriangle,
  };
  if (result.unresolved?.length || result.status === "needs_review" || result.status === "possible_misuse" || classifierAlert) return {
    title: result.unresolved?.length || !classifierAlert ? "Requiere revisión manual" : "No se identificó un problema concreto",
    description: result.unresolved?.length
      ? "Hay parámetros que no se pudieron resolver. Revisalos antes de decidir si hace falta corregir el código."
      : classifierAlert || result.status === "possible_misuse"
        ? "El ML generó una alerta, pero no pudo indicar un defecto ni una corrección específica. No modifiques el código basándote únicamente en esta alerta."
        : "No se pudieron completar los controles de parámetros. Revisá manualmente el fragmento antes de decidir cambios.",
    tone: "border-amber-500/40 bg-amber-500/5", icon: AlertTriangle,
  };
  if (result.status === "not_evaluable") return {
    title: "No se pudo evaluar este código",
    description: "No se reconocieron llamadas criptográficas soportadas. Probá con un archivo Java que use las APIs de cifrado compatibles.",
    tone: "border-border bg-muted/30", icon: CircleHelp,
  };
  return {
    title: "Sin problemas en los controles aplicados",
    description: "No se encontraron configuraciones deficientes en los parámetros que se pudieron comprobar.",
    tone: "border-emerald-500/40 bg-emerald-500/5", icon: CircleCheck,
  };
}

export default function CryptoMLPage() {
  const [filename, setFilename] = useState("source.java");
  const [source, setSource] = useState("");
  const [result, setResult] = useState<Review | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [needsLogin, setNeedsLogin] = useState(false);
  const summary = result ? summarize(result) : null;

  async function analyze() {
    setBusy(true);
    setError("");
    setNeedsLogin(false);
    setResult(null);
    try {
      setResult(await api.post<Review>("/crypto-ml/analyze", { body: { filename, source } }));
    } catch (err) {
      const unauthorized = err instanceof ApiError && err.status === 401;
      setNeedsLogin(unauthorized);
      setError(unauthorized ? "Tu sesión venció o no está disponible. Volvé a iniciar sesión para analizar el archivo." : err instanceof Error ? err.message : "No se pudo analizar el archivo");
    } finally {
      setBusy(false);
    }
  }

  function download() {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "sast-review.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div lang="es" className="min-w-0 space-y-6">
      <PageHeader title="SAST" subtitle="Subí un archivo Java o pegá su código para revisar la configuración de cifrado." />
      <Card>
        <CardHeader><CardTitle>Archivo Java · hasta 100 KB</CardTitle></CardHeader>
        <CardContent className="grid gap-4">
          <p className="text-sm text-muted-foreground">El código se analiza sin ejecutarlo ni guardarlo.</p>
          <label className="grid gap-2 text-sm">Seleccionar archivo .java
            <Input type="file" className="h-auto min-h-10 cursor-pointer py-2 file:mr-3 file:text-[var(--accent-bright)]" accept=".java,.jav" disabled={busy} onChange={async (event) => {
              const file = event.target.files?.[0];
              setResult(null); setSource(""); setError("");
              if (!file) return;
              const selectedName = file.name.trim();
              // Windows can expose a DOS 8.3 alias instead of the long filename.
              const shortJavaName = /^[a-z0-9_]{1,6}~[0-9]+\.jav$/i.test(selectedName);
              const javaName = shortJavaName ? selectedName.slice(0, -4) + ".java" : selectedName;
              setFilename(javaName);
              if (!javaName.toLowerCase().endsWith(".java")) {
                setError(`El navegador recibió el archivo «${file.name}». Su nombre debe terminar en .java; verificá que no sea .java.txt o dataset.jsonl.`);
                return;
              }
              if (file.size > 100_000) {
                setError(`«${file.name}» pesa ${file.size.toLocaleString("es-AR")} bytes. El máximo es 100.000 bytes.`);
                return;
              }
              try {
                const text = await file.text();
                const utf8Bytes = new TextEncoder().encode(text).byteLength;
                if (utf8Bytes > 100_000) {
                  setError(`El contenido ocupa ${utf8Bytes.toLocaleString("es-AR")} bytes en UTF-8. El máximo es 100.000 bytes.`);
                  return;
                }
                setSource(text);
              }
              catch { setError(`No se pudo leer «${file.name}». Intentá copiar su contenido en el cuadro de código.`); }
            }} />
          </label>
          <label className="grid gap-2 text-sm">Código a revisar ({filename})
            <Textarea className="min-h-40 w-full p-3 font-mono text-xs" value={source} maxLength={100_000} disabled={busy} onChange={(event) => { setSource(event.target.value); setResult(null); }} spellCheck={false} />
          </label>
          <Button onClick={analyze} disabled={busy || !source.trim()}>{busy ? "Analizando…" : "Analizar con modelo local"}</Button>
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          {/* Reload the auth provider too, so stale authenticated state cannot bounce back from login. */}
          {needsLogin && <a className="text-sm font-medium underline underline-offset-4" href="/login?next=%2Fcrypto-ml">Volver a iniciar sesión</a>}
        </CardContent>
      </Card>
      {result && summary && <Card aria-live="polite" className={summary.tone}>
        <CardHeader>
          <p className="font-mono text-xs break-all text-muted-foreground">Resultado · {result.filename}</p>
          <CardTitle><h2 className="flex items-center gap-2"><summary.icon className="size-5 shrink-0" aria-hidden="true" />{summary.title}</h2></CardTitle>
          <p className="text-sm">{summary.description}</p>
        </CardHeader>
        <CardContent className="grid gap-4 text-sm">
          <section className="grid gap-3" aria-label="Comprobaciones de parámetros">
            {!!result.findings?.length && <h3 className="font-semibold">Qué revisar y cómo corregirlo</h3>}
            {result.findings?.length ? result.findings.map((finding, index) => <div className="rounded-md border p-4" key={`${finding.id}-${finding.line}-${index}`}>
              <p className="font-semibold">{finding.title}</p>
              <p className="text-xs text-muted-foreground">Línea {finding.line ?? "no disponible"}</p>
              <p className="mt-2">{finding.recommendation}</p>
              <details className="mt-3 text-xs">
                <summary className="cursor-pointer font-medium">Ver evidencia y referencia</summary>
              <p className="mt-2 font-mono break-all">Valor observado: {String(finding.value)}</p>
              {finding.materialOriginLine && <p className="text-xs text-muted-foreground">Origen o derivación del material: línea {finding.materialOriginLine}. Los literales de la evidencia están redactados.</p>}
              <pre className="my-2 overflow-auto whitespace-pre-wrap rounded bg-muted p-3 text-xs">{finding.evidence}</pre>
              <p className="mt-2 text-xs text-muted-foreground">{finding.reference}</p>
              </details>
            </div>) : null}
          </section>
          {!!result.unresolved?.length && <section aria-label="Revisión manual"><h3 className="font-semibold">No resuelto automáticamente</h3><ul className="list-disc pl-5">{result.unresolved.map((item, index) => <li key={index}>Línea {item.line ?? "no disponible"}: {item.reason}</li>)}</ul></section>}
          {!!result.contextNotes?.length && <section aria-label="Sobre este código" className="rounded-md border bg-background/60 p-3">
            {result.contextNotes.map((note, index) => <p key={index}>{note}</p>)}
          </section>}
          {result.ml?.context?.status === "unavailable" && <p className="text-xs text-muted-foreground">El análisis con ML no estuvo disponible; el resultado corresponde a los controles que se pudieron aplicar.</p>}
          <p className="text-xs text-muted-foreground">El análisis tiene un alcance limitado y no garantiza la seguridad completa del archivo.</p>
          <Button variant="outline" onClick={download}>Descargar informe</Button>
        </CardContent>
      </Card>}
    </div>
  );
}
