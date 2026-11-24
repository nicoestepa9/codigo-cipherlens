import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import CryptoMLPage from "@/app/crypto-ml/page";

vi.mock("@/services/apiClient", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/services/apiClient")>(),
  api: { post: vi.fn() },
}));
afterEach(cleanup);

describe("Clear review summary", () => {
  it("offers sign-in when the session is missing instead of displaying an English API error", async () => {
    const { api, ApiError } = await import("@/services/apiClient");
    vi.mocked(api.post).mockRejectedValueOnce(new ApiError(401, "Missing credentials"));
    render(<CryptoMLPage />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "class Demo {}" } });
    fireEvent.click(screen.getByRole("button", { name: "Analizar con modelo local" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Volvé a iniciar sesión");
    expect(screen.getByRole("link", { name: "Volver a iniciar sesión" })).toHaveAttribute("href", "/login?next=%2Fcrypto-ml");
    expect(screen.getByRole("textbox")).toHaveValue("class Demo {}");
  });
  const base = {
    filename: "Demo.java", modelVersion: "test", datasetRevision: "test",
    misuseScore: null, scoreMeaning: "test", limitations: [], recommendation: "Revisar",
    findings: [], unresolved: [], observations: [],
  };

  async function show(payload: Record<string, unknown>) {
    const { api } = await import("@/services/apiClient");
    vi.mocked(api.post).mockResolvedValue(payload);
    render(<CryptoMLPage />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "class Demo {}" } });
    fireEvent.click(screen.getByRole("button", { name: "Analizar con modelo local" }));
    await screen.findByText("Resultado · Demo.java");
  }

  it("keeps the finding and action visible even when ML is negative, with evidence collapsed", async () => {
    await show({ ...base, status: "possible_misuse",
      findings: [{ id: "RSA", title: "RSA de 1024 bits", line: 8, evidence: "g.initialize(1024);", value: 1024, recommendation: "Usar al menos 2048 bits", reference: "Control RSA" }],
      ml: { status: "applied", predictions: [], outOfScope: [], supportedTransformations: [], context: { status: "applied", classification: "no_indication", score: 0.1, reason: "test" } },
    });
    expect(screen.getByRole("heading", { name: "Hay configuraciones que requieren atención" })).toBeVisible();
    expect(screen.getByText("Usar al menos 2048 bits")).toBeVisible();
    expect(screen.getByText("Línea 8")).toBeVisible();
    expect(screen.getByText("g.initialize(1024);")).not.toBeVisible();
    fireEvent.click(screen.getByText("Ver evidencia y referencia"));
    expect(screen.getByText("g.initialize(1024);")).toBeVisible();
  });

  it("does not present an ML-only alert as a confirmed configuration problem", async () => {
    await show({ ...base, status: "possible_misuse", ml: { status: "applied", predictions: [], outOfScope: [], supportedTransformations: [], context: { status: "applied", classification: "possible_misuse", score: 1, reason: "test" } } });
    expect(screen.getByRole("heading", { name: "No se identificó un problema concreto" })).toBeVisible();
    expect(screen.getByText(/no pudo indicar un defecto ni una corrección específica/)).toBeVisible();
    expect(screen.queryByText("Qué revisar y cómo corregirlo")).not.toBeInTheDocument();
  });

  it("keeps unresolved input out of the clean result without inventing an ML alert", async () => {
    await show({ ...base, status: "needs_review", unresolved: [{ line: 4, reason: "Tamaño RSA no resuelto" }] });
    expect(screen.getByRole("heading", { name: "Requiere revisión manual" })).toBeVisible();
    expect(screen.getByText(/Tamaño RSA no resuelto/)).toBeVisible();
    expect(screen.queryByText(/Un clasificador señaló/)).not.toBeInTheDocument();
  });

  it("shows limited clean results without claiming the file is secure", async () => {
    await show({ ...base, status: "no_indication" });
    expect(screen.getByRole("heading", { name: "Sin problemas en los controles aplicados" })).toBeVisible();
    expect(screen.getByText(/no garantiza la seguridad completa/)).toBeVisible();
  });

  it("distinguishes unsupported code from a clean result", async () => {
    await show({ ...base, status: "not_evaluable" });
    expect(screen.getByRole("heading", { name: "No se pudo evaluar este código" })).toBeVisible();
    expect(screen.queryByText("Sin problemas en los controles aplicados")).not.toBeInTheDocument();
  });

  it("explains the decryption context without inventing a defect or a correction", async () => {
    await show({ ...base, status: "needs_review",
      contextNotes: ["El IV fijo se usa para descifrar (DECRYPT_MODE). Eso, por sí solo, no demuestra una mala configuración."],
      ml: { status: "applied", predictions: [], outOfScope: [], supportedTransformations: [], context: { status: "applied", classification: "possible_misuse", score: 1, reason: "Technical model detail" } },
    });
    expect(screen.getByRole("heading", { name: "No se identificó un problema concreto" })).toBeVisible();
    expect(screen.getByText(/El IV fijo se usa para descifrar/)).toBeVisible();
    expect(screen.queryByText(/Technical model detail|Puntaje|1.000/)).not.toBeInTheDocument();
    expect(screen.queryByText("Qué revisar y cómo corregirlo")).not.toBeInTheDocument();
  });
});

describe("Concise contextual result", () => {
  it("omits scores, training details and metrics even when the response includes them", async () => {
    const { api } = await import("@/services/apiClient");
    vi.mocked(api.post).mockResolvedValue({
      filename: "Example.java", modelVersion: "context-test", datasetRevision: "CryptoLLM",
      status: "needs_review", misuseScore: 0.9, scoreMeaning: "Salida estadística",
      limitations: [], recommendation: "Revisar el contexto", findings: [],
      ml: { status: "applied", predictions: [], outOfScope: [], supportedTransformations: [], context: {
        status: "applied", score: 0.9, classification: "possible_misuse", reason: "No identifica una línea.",
        trainingSamples: 6929, validationSamples: 2309, testSamples: 2309,
        semanticTrainingSamples: 103, numericTrainingSamples: 32,
        evaluation: { test: { metrics: { precision: 0.95, recall: 0.94, f1: 0.947, accuracy: 0.94 }, coverage: 0.83, total: 2309 } },
        externalEvaluation: { covered: 68, metrics: { f1: 0.808, recall: 0.714 } },
      } },
    });
    render(<CryptoMLPage />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "class Example {}" } });
    fireEvent.click(screen.getByRole("button", { name: "Analizar con modelo local" }));
    expect(await screen.findByRole("heading", { name: "No se identificó un problema concreto" })).toBeVisible();
    expect(screen.queryByText(/CryptoLLM|Puntaje|entrenamiento|F1|Transferencia a/)).not.toBeInTheDocument();
    expect(screen.queryByText("Ver análisis técnico y métricas")).not.toBeInTheDocument();
    expect(screen.queryByText(/Línea 1 ·/)).not.toBeInTheDocument();
  });

  it("reports an unavailable local model explicitly", async () => {
    const { api } = await import("@/services/apiClient");
    vi.mocked(api.post).mockResolvedValue({
      filename: "Example.java", modelVersion: "legacy", datasetRevision: "legacy",
      status: "not_evaluable", misuseScore: null, scoreMeaning: "test", limitations: [], recommendation: "Revisar",
      ml: { status: "not_applicable", predictions: [], outOfScope: [], supportedTransformations: [], context: { status: "unavailable", reason: "No se entrenó el modelo contextual local." } },
    });
    render(<CryptoMLPage />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "class Example {}" } });
    fireEvent.click(screen.getByRole("button", { name: "Analizar con modelo local" }));
    expect(await screen.findByText(/El análisis con ML no estuvo disponible/)).toBeVisible();
    expect(screen.queryByText(/Test interno agrupado:/)).not.toBeInTheDocument();
  });
});

describe("Crypto ML file selection", () => {
  it("accepts a Java file of 1792 bytes without a MIME type", async () => {
    render(<CryptoMLPage />);
    const source = "class Example {}".padEnd(1792, " ");
    const file = new File([source], "InsecureAsymmetricCipherABICase2.java", { type: "" });
    Object.defineProperty(file, "text", { value: async () => source });
    fireEvent.change(screen.getByLabelText("Seleccionar archivo .java"), { target: { files: [file] } });
    await waitFor(() => expect(screen.getByRole("textbox")).toHaveValue(source));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Analizar con modelo local" })).toBeEnabled();
  });

  it("reports the actual filename for an extension error", () => {
    render(<CryptoMLPage />);
    const file = new File(["class Example {}"], "Example.java.txt");
    fireEvent.change(screen.getByLabelText("Seleccionar archivo .java"), { target: { files: [file] } });
    expect(screen.getByRole("alert")).toHaveTextContent("Example.java.txt");
    expect(screen.getByRole("alert")).not.toHaveTextContent("pesa");
  });

  it("distinguishes oversized files from extension errors", () => {
    render(<CryptoMLPage />);
    const file = new File(["x".repeat(100001)], "Example.java");
    fireEvent.change(screen.getByLabelText("Seleccionar archivo .java"), { target: { files: [file] } });
    expect(screen.getByRole("alert")).toHaveTextContent("100.001 bytes");
  });

  it("accepts the Windows alias and submits a .java filename", async () => {
    const { api } = await import("@/services/apiClient");
    vi.mocked(api.post).mockResolvedValue({
      filename: "INCAE1~1.java", modelVersion: "test", datasetRevision: "test",
      status: "no_indication", misuseScore: 0.1, scoreMeaning: "test",
      limitations: [], recommendation: "review",
    });
    render(<CryptoMLPage />);
    const source = 'class Example { Cipher c = Cipher.getInstance("RSA"); }';
    const file = new File([source], "INCAE1~1.JAV");
    Object.defineProperty(file, "text", { value: async () => source });
    fireEvent.change(screen.getByLabelText("Seleccionar archivo .java"), { target: { files: [file] } });
    await waitFor(() => expect(screen.getByRole("textbox")).toHaveValue(source));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Analizar con modelo local" }));
    await waitFor(() => expect(api.post).toHaveBeenCalledWith("/crypto-ml/analyze", {
      body: { filename: "INCAE1~1.java", source },
    }));
  });

  it("rejects unrelated .jav files", () => {
    render(<CryptoMLPage />);
    const file = new File(["class Example {}"], "Example.jav");
    fireEvent.change(screen.getByLabelText("Seleccionar archivo .java"), { target: { files: [file] } });
    expect(screen.getByRole("alert")).toHaveTextContent("Example.jav");
  });

  it("shows RSA evidence separately from the ML abstention", async () => {
    const { api } = await import("@/services/apiClient");
    vi.mocked(api.post).mockResolvedValue({
      filename: "Example.java", modelVersion: "v3-test", datasetRevision: "test",
      status: "possible_misuse", misuseScore: null, scoreMeaning: "test",
      limitations: [], recommendation: "Revisar evidencias",
      findings: [{ id: "JAVA-RSA-SIZE", title: "Tamaño RSA inferior a 2048 bits", line: 5, evidence: "g.initialize(1024);", value: 1024, recommendation: "Usar al menos 2048 bits", reference: "Control RSA" }],
      observations: [], unresolved: [],
      ml: { status: "not_applicable", predictions: [], outOfScope: [], supportedTransformations: ["AES/GCM/NOPADDING", "DES/CBC/PKCS5PADDING"] },
    });
    render(<CryptoMLPage />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "class Example {}" } });
    fireEvent.click(screen.getByRole("button", { name: "Analizar con modelo local" }));
    expect(await screen.findByText("Tamaño RSA inferior a 2048 bits")).toBeInTheDocument();
    expect(screen.getByText("g.initialize(1024);")).toBeInTheDocument();
    expect(screen.queryByText(/El modelo de parámetros se abstuvo/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Puntaje del clasificador:/)).not.toBeInTheDocument();
  });

  it("shows the learned RSA policy separately from the deterministic finding", async () => {
    const { api } = await import("@/services/apiClient");
    vi.mocked(api.post).mockResolvedValue({
      filename: "Example.java", modelVersion: "v4-test", datasetRevision: "policy",
      status: "possible_misuse", misuseScore: 1, scoreMeaning: "Puntaje de política",
      limitations: [], recommendation: "Revisar evidencias",
      findings: [{ id: "JAVA-RSA-SIZE", title: "Tamaño RSA inferior a 2048 bits", line: 5, evidence: "g.initialize(1024);", value: 1024, recommendation: "Usar al menos 2048 bits", reference: "Control RSA" }],
      observations: [], unresolved: [],
      ml: { status: "applied", predictions: [], outOfScope: [], supportedTransformations: [], rsaDomain: [512, 16384], rsaPredictions: [{ line: 5, bits: 1024, score: 1, classification: "below_size_minimum" }] },
    });
    render(<CryptoMLPage />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "class Example {}" } });
    fireEvent.click(screen.getByRole("button", { name: "Analizar con modelo local" }));
    expect(await screen.findByText("Tamaño RSA inferior a 2048 bits")).toBeVisible();
    expect(screen.queryByText(/no cumple el mínimo de tamaño aprendido/)).not.toBeInTheDocument();
    expect(screen.queryByText(/El modelo de parámetros se abstuvo/)).not.toBeInTheDocument();
  });

  it("renders redacted material evidence and its origin without inventing an ML finding", async () => {
    const { api } = await import("@/services/apiClient");
    vi.mocked(api.post).mockResolvedValue({
      filename: "Material.java", modelVersion: "v5-test", datasetRevision: "test",
      status: "possible_misuse", misuseScore: 0, scoreMeaning: "Solo transformación",
      limitations: [], recommendation: "Retirar la clave del código",
      findings: [{ id: "JAVA-EMBEDDED-KEY", title: "Posible clave simétrica incrustada usada en Cipher.init", line: 8, materialOriginLine: 4, evidence: "c.init(Cipher.ENCRYPT_MODE,key); [literal redactado]", value: "material de clave constante [redactado]", recommendation: "Usar un gestor de secretos", reference: "Procedencia local" }],
      observations: [], unresolved: [],
      ml: { status: "applied", predictions: [{ line: 6, transformation: "AES/GCM/NoPadding", score: 0, classification: "no_indication" }], outOfScope: [], supportedTransformations: ["AES/GCM/NOPADDING"] },
    });
    render(<CryptoMLPage />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "class Demo {}" } });
    fireEvent.click(screen.getByRole("button", { name: "Analizar con modelo local" }));
    expect(await screen.findByText("Posible clave simétrica incrustada usada en Cipher.init")).toBeInTheDocument();
    expect(screen.getByText(/Origen o derivación del material: línea 4/)).toBeInTheDocument();
    expect(screen.queryByText(/AES\/GCM\/NoPadding.*sin indicios/)).not.toBeInTheDocument();
  });
});
