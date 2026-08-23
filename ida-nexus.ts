import { mkdtemp, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
  formatSize,
  highlightCode,
  keyHint,
  truncateHead,
  type ExtensionAPI,
  type ExtensionContext,
  type Theme,
} from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";

const PACKAGE_ROOT = dirname(fileURLToPath(import.meta.url));
const PACKAGE_VERSION = (
  createRequire(import.meta.url)("./package.json") as { version: string }
).version;
// The MCP SDK requires a request timer. Use Node's largest reliable delay so
// Pi does not impose a meaningful operation cutoff; backends enforce their own
// operation-specific timeouts.
const CALL_TIMEOUT_MS = 2_147_483_647;
const STDERR_CAPTURE_MAX_CHARS = 1024 * 1024;
const STATUS_WIDGET_KEY = "ida-nexus:status-bar";
const STATUS_HIDE_DELAY_MS = 4000;
const DISCOVERABLE_TOOLS_FLAG = "ida-tools-discoverable";

type PiContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string };

async function saveStartupLog(output: string): Promise<string | undefined> {
  if (!output.trim()) return undefined;

  try {
    const dir = await mkdtemp(join(tmpdir(), "pi-ida-mcp-startup-"));
    const path = join(dir, "stderr.log");
    await writeFile(path, output, "utf8");
    return path;
  } catch {
    return undefined;
  }
}

function renderToolCall(
  toolName: string,
  args: Record<string, unknown> | undefined,
  theme: Theme,
  expanded: boolean,
): Text {
  let text = theme.fg("toolTitle", theme.bold(toolName));
  const mcpToolName = toolName.startsWith("ida_")
    ? toolName.slice(4)
    : toolName;

  if (mcpToolName === "execute_python" && typeof args?.code === "string") {
    if (typeof args.instance_id === "string") {
      text += ` ${theme.fg("muted", args.instance_id)}`;
    }

    const lines = highlightCode(args.code.replaceAll("\t", "    "), "python");
    const maxLines = expanded ? lines.length : 10;
    const displayed = lines.slice(0, maxLines);
    text += `\n\n${displayed.join("\n")}`;

    const remaining = lines.length - displayed.length;
    if (remaining > 0) {
      text +=
        theme.fg("muted", `\n... (${remaining} more lines,`) +
        ` ${keyHint("app.tools.expand", "to expand")}${theme.fg("muted", ")")}`;
    }
    return new Text(text, 0, 0);
  }

  const serialized = args ? JSON.stringify(args, null, 2) : undefined;
  if (serialized && serialized !== "{}") {
    text += `\n\n${theme.fg("toolOutput", serialized)}`;
  }
  return new Text(text, 0, 0);
}

export default function idaNexus(pi: ExtensionAPI) {
  const agentKind = "arktype" in pi && "zod" in pi ? "omp" : "pi";
  if (agentKind === "omp") {
    pi.registerFlag(DISCOVERABLE_TOOLS_FLAG, {
      description:
        "Mount IDA tools under xd:// instead of exposing them directly in OMP",
      type: "boolean",
      default: false,
    });
  }

  const sessionPathField = `${agentKind}_session_path`;
  let client: Client | undefined;
  let connectingClient: Client | undefined;
  let startupPromise: Promise<void> | undefined;
  let sessionRunning = false;
  let statusHideTimer: NodeJS.Timeout | undefined;
  let statusWidgetMounted = false;
  let requestStatusRender: (() => void) | undefined;
  let statusWidgetState:
    | {
        state: "starting" | "ready" | "error";
        details: string[];
      }
    | undefined;

  const clearStatusWidget = (ctx: ExtensionContext) => {
    if (statusHideTimer) {
      clearTimeout(statusHideTimer);
      statusHideTimer = undefined;
    }
    statusWidgetState = undefined;
    statusWidgetMounted = false;
    requestStatusRender = undefined;
    ctx.ui.setWidget(STATUS_WIDGET_KEY, undefined);
  };

  const showStatus = (
    ctx: ExtensionContext,
    state: "starting" | "ready" | "error",
    detail?: string | string[],
  ) => {
    if (statusHideTimer) {
      clearTimeout(statusHideTimer);
      statusHideTimer = undefined;
    }
    statusWidgetState = {
      state,
      details: detail ? (Array.isArray(detail) ? detail : [detail]) : [],
    };

    // Pi currently removes and reinserts a widget every time setWidget() is
    // called, which changes Map insertion order relative to other extensions.
    // Mount once and mutate our component state so adjacent status widgets do
    // not swap positions while their asynchronous connections settle.
    if (!statusWidgetMounted) {
      statusWidgetMounted = true;
      ctx.ui.setWidget(
        STATUS_WIDGET_KEY,
        (tui, theme) => {
          const requestRender = () => tui.requestRender();
          requestStatusRender = requestRender;
          return {
            invalidate() {},
            dispose() {
              if (requestStatusRender === requestRender) {
                requestStatusRender = undefined;
              }
            },
            render(): string[] {
              const current = statusWidgetState;
              if (!current) return [];
              const icon =
                current.state === "ready"
                  ? theme.fg("success", "●")
                  : current.state === "error"
                    ? theme.fg("error", "●")
                    : theme.fg("warning", "○");
              const label =
                current.state === "starting"
                  ? "starting…"
                  : current.state === "ready"
                    ? "ready"
                    : "startup failed";
              const header = [
                `${icon} ${theme.fg("accent", theme.bold("IDA MCP"))}`,
                theme.fg(current.state === "error" ? "error" : "muted", label),
              ].join(theme.fg("dim", "  ·  "));
              const detailLines = current.details.map((line) =>
                theme.fg("dim", `  ${line}`),
              );
              return [header, ...detailLines];
            },
          };
        },
        { placement: "belowEditor" },
      );
    } else {
      requestStatusRender?.();
    }

    if (state === "ready") {
      statusHideTimer = setTimeout(
        () => clearStatusWidget(ctx),
        STATUS_HIDE_DELAY_MS,
      );
    }
  };

  const startMcp = async (ctx: ExtensionContext): Promise<void> => {
    if (client || connectingClient) return;

    const next = new Client({ name: "ida", version: PACKAGE_VERSION });
    connectingClient = next;
    let capturedStderr = "";
    let captureStderr = true;
    const transport = new StdioClientTransport({
      command: "uv",
      args: [
        "run",
        "--with=ida-hcli",
        "--project",
        PACKAGE_ROOT,
        "ida-nexus",
        "mcp",
        `--agent=${agentKind}`,
      ],
      cwd: PACKAGE_ROOT,
      stderr: "pipe",
      env: {
        ...(process.env.IDA_NEXUS_ID
          ? { IDA_NEXUS_ID: process.env.IDA_NEXUS_ID }
          : {}),
        ...(process.env.IDAUSR ? { IDAUSR: process.env.IDAUSR } : {}),
        ...(process.env.IDA_NEXUS_STATE_DIR
          ? { IDA_NEXUS_STATE_DIR: process.env.IDA_NEXUS_STATE_DIR }
          : {}),
      },
    });

    transport.stderr?.on("data", (chunk: unknown) => {
      if (!captureStderr) return;
      const text = Buffer.isBuffer(chunk)
        ? chunk.toString("utf8")
        : String(chunk);
      capturedStderr = (capturedStderr + text).slice(-STDERR_CAPTURE_MAX_CHARS);
    });

    try {
      await next.connect(transport);
      const { tools } = await next.listTools();
      if (!sessionRunning || connectingClient !== next) {
        await next.close().catch(() => undefined);
        return;
      }
      client = next;
      connectingClient = undefined;
      const ompToolOptions =
        agentKind === "omp"
          ? {
              loadMode:
                pi.getFlag(DISCOVERABLE_TOOLS_FLAG) === true
                  ? ("discoverable" as const)
                  : ("essential" as const),
            }
          : {};
      for (const tool of tools) {
        const piToolName = tool.name.startsWith("ida_")
          ? tool.name
          : `ida_${tool.name}`;
        pi.registerTool({
          ...ompToolOptions,
          name: piToolName,
          label: tool.annotations?.title ?? `IDA ${tool.name}`,
          description: tool.description ?? `Call the IDA MCP ${tool.name} tool`,
          // MCP and Pi both use JSON Schema for tool inputs. The SDK's type is
          // structurally compatible, but it is not branded as a TypeBox schema.
          parameters: tool.inputSchema as any,
          renderCall(args, theme, context) {
            return renderToolCall(
              piToolName,
              args as Record<string, unknown> | undefined,
              theme,
              context.expanded,
            );
          },
          async execute(_id, params, signal, onUpdate, ctx) {
            if (!client) throw new Error("The IDA MCP server is not connected");

            const sessionPath = ctx.sessionManager.getSessionFile();
            const result = await client.callTool(
              {
                name: tool.name,
                arguments: params as Record<string, unknown>,
                ...(sessionPath
                  ? { _meta: { [sessionPathField]: sessionPath } }
                  : {}),
              },
              undefined,
              {
                signal,
                timeout: CALL_TIMEOUT_MS,
                onprogress(progress) {
                  const total = progress.total ? `/${progress.total}` : "";
                  onUpdate?.({
                    content: [
                      {
                        type: "text",
                        text: `IDA MCP progress: ${progress.progress}${total}`,
                      },
                    ],
                    details: {},
                  });
                },
              },
            );

            if (!Array.isArray(result.content)) {
              return {
                content: [
                  {
                    type: "text",
                    text: JSON.stringify(result.toolResult ?? result, null, 2),
                  },
                ],
                details: {},
              };
            }

            const images: PiContent[] = [];
            const textParts: string[] = [];
            for (const item of result.content as Array<any>) {
              if (item.type === "text") textParts.push(item.text);
              else if (item.type === "image") {
                images.push({
                  type: "image",
                  data: item.data,
                  mimeType: item.mimeType,
                });
              } else textParts.push(JSON.stringify(item, null, 2));
            }
            if (textParts.length === 0 && result.structuredContent) {
              textParts.push(JSON.stringify(result.structuredContent, null, 2));
            }

            const fullText = textParts.join("\n");
            const truncated = truncateHead(fullText, {
              maxBytes: DEFAULT_MAX_BYTES,
              maxLines: DEFAULT_MAX_LINES,
            });
            let text = truncated.content;
            let fullOutputPath: string | undefined;
            if (truncated.truncated) {
              const dir = await mkdtemp(join(tmpdir(), "pi-ida-mcp-"));
              fullOutputPath = join(dir, `${tool.name}.txt`);
              await writeFile(fullOutputPath, fullText, "utf8");
              text += `\n\n[Output truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}. Full output: ${fullOutputPath}]`;
            }

            if (result.isError) throw new Error(text || `${tool.name} failed`);
            return {
              content: [
                ...(text ? [{ type: "text" as const, text }] : []),
                ...images,
              ],
              details: fullOutputPath ? { fullOutputPath } : {},
            };
          },
        });
      }

      captureStderr = false;
      capturedStderr = "";
      showStatus(ctx, "ready");
    } catch (error) {
      if (connectingClient === next) connectingClient = undefined;
      if (client === next) client = undefined;
      await next.close().catch(() => undefined);
      if (!sessionRunning) return;

      const message = error instanceof Error ? error.message : String(error);
      const logContents = capturedStderr
        ? `IDA MCP failed to start: ${message}\n\n${capturedStderr}`
        : `IDA MCP failed to start: ${message}\n`;
      const logPath = await saveStartupLog(logContents);
      const details = [message, ...(logPath ? [`Log: ${logPath}`] : [])];
      showStatus(ctx, "error", details);
    }
  };

  pi.on("session_start", (_event, ctx) => {
    if (startupPromise) return;
    sessionRunning = true;
    showStatus(ctx, "starting");
    startupPromise = startMcp(ctx);
  });

  pi.on("input", async () => {
    await startupPromise;
    return { action: "continue" };
  });

  pi.on("session_shutdown", async (_event, ctx) => {
    sessionRunning = false;
    clearStatusWidget(ctx);
    const active = client;
    const connecting = connectingClient;
    client = undefined;
    connectingClient = undefined;
    startupPromise = undefined;
    await Promise.all([
      active?.close(),
      connecting && connecting !== active ? connecting.close() : undefined,
    ]);
  });
}
