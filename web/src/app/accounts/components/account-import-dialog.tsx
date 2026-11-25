"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState, type ChangeEvent } from "react";
import {
  ArrowLeft,
  CheckCircle2,
  Copy,
  ExternalLink,
  FileJson,
  FileText,
  Files,
  KeyRound,
  LoaderCircle,
  LogIn,
  ServerCog,
  Upload,
  X,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import {
  createAccounts,
  fetchAccounts,
  fetchOAuthBatchImportJob,
  finishOAuthLogin,
  startOAuthBatchImport,
  startOAuthLogin,
  type Account,
  type AccountImportPayload,
  type OAuthBatchImportJob,
  type OAuthLoginStartResponse,
} from "@/lib/api";
import { cn } from "@/lib/utils";

type ImportMethod = "menu" | "token" | "session" | "codex-auth" | "account-json" | "oauth" | "oauth-batch";

type AccountImportDialogProps = {
  disabled?: boolean;
  onImported: (items: Account[]) => void;
};

type PendingAccountJsonImport = {
  tokens: string[];
  accounts: AccountImportPayload[];
  parsedAccountCount: number;
  errorCount: number;
};

const sessionUrl = "https://chatgpt.com/api/auth/session";

function splitTokens(value: string) {
  return value
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function countCredentialLines(value: string) {
  return value
    .replace(/^\uFEFF/, "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0 && !item.startsWith("#")).length;
}

function getSessionAccessToken(value: unknown) {
  const token = (value as { accessToken?: unknown })?.accessToken;
  return typeof token === "string" ? token.trim() : "";
}

function getAccountJsonAccount(value: unknown): AccountImportPayload | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const raw = value as Record<string, unknown>;
  const tokenValue = raw.access_token ?? raw.accessToken;
  const token = typeof tokenValue === "string" ? tokenValue.trim() : "";
  if (!token) {
    return null;
  }

  const payload: AccountImportPayload = {
    ...raw,
    access_token: token,
    source_type: "codex",
  };
  delete payload.accessToken;
  if (payload.type === "codex") {
    payload.export_type = "codex";
    delete payload.type;
  }
  return payload;
}

function getAccountJsonAccounts(value: unknown): AccountImportPayload[] {
  if (Array.isArray(value)) {
    return value
      .map((item) => getAccountJsonAccount(item))
      .filter((item): item is AccountImportPayload => Boolean(item));
  }

  const singleAccount = getAccountJsonAccount(value);
  if (singleAccount) {
    return [singleAccount];
  }

  if (value && typeof value === "object") {
    const raw = value as Record<string, unknown>;
    const nested = raw.accounts ?? raw.items;
    if (Array.isArray(nested)) {
      return nested
        .map((item) => getAccountJsonAccount(item))
        .filter((item): item is AccountImportPayload => Boolean(item));
    }
  }

  return [];
}

function getCodexAuthAccount(value: unknown): AccountImportPayload | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const raw = value as Record<string, unknown>;
  const tokenValue = raw.access_token ?? raw.accessToken;
  const token = typeof tokenValue === "string" ? tokenValue.trim() : "";
  if (!token) {
    return null;
  }

  const payload: AccountImportPayload = {
    ...raw,
    access_token: token,
    export_type: "codex",
    source_type: "codex",
  };
  delete payload.accessToken;
  if (payload.type === "codex") {
    delete payload.type;
  }
  return payload;
}

function readFileAsText(file: File) {
  return new Promise<string>((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(typeof reader.result === "string" ? reader.result : "");
    reader.onerror = () => reject(reader.error ?? new Error(`读取文件失败: ${file.name}`));
    reader.readAsText(file);
  });
}

function MethodCard({
  title,
  description,
  icon: Icon,
  onClick,
}: {
  title: string;
  description: string;
  icon: typeof KeyRound;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full rounded-2xl border border-stone-200 bg-white p-0 text-left transition hover:border-stone-300 hover:bg-stone-50"
    >
      <Card className="rounded-2xl border-0 bg-transparent shadow-none">
        <CardContent className="flex items-start gap-4 p-4">
          <div className="rounded-xl bg-stone-100 p-3 text-stone-700">
            <Icon className="size-5" />
          </div>
          <div className="space-y-1">
            <div className="text-sm font-semibold text-stone-900">{title}</div>
            <div className="text-sm leading-6 text-stone-500">{description}</div>
          </div>
        </CardContent>
      </Card>
    </button>
  );
}

export function AccountImportDialog({ disabled, onImported }: AccountImportDialogProps) {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [method, setMethod] = useState<ImportMethod>("menu");
  const [tokenInput, setTokenInput] = useState("");
  const [sessionInput, setSessionInput] = useState("");
  const [codexAuthInput, setCodexAuthInput] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [pendingAccountJsonImport, setPendingAccountJsonImport] = useState<PendingAccountJsonImport | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [oauthEmailHint, setOauthEmailHint] = useState("");
  const [oauthSession, setOauthSession] = useState<OAuthLoginStartResponse | null>(null);
  const [oauthCallbackInput, setOauthCallbackInput] = useState("");
  const [oauthStarting, setOauthStarting] = useState(false);
  const [batchFile, setBatchFile] = useState<File | null>(null);
  const [batchFileLineCount, setBatchFileLineCount] = useState(0);
  const [batchTextInput, setBatchTextInput] = useState("");
  const [batchJob, setBatchJob] = useState<OAuthBatchImportJob | null>(null);

  const txtInputRef = useRef<HTMLInputElement | null>(null);
  const accountJsonInputRef = useRef<HTMLInputElement | null>(null);
  const oauthBatchFileInputRef = useRef<HTMLInputElement | null>(null);
  const batchPollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const batchPollSeqRef = useRef(0);

  const stopBatchPolling = () => {
    batchPollSeqRef.current += 1;
    if (batchPollTimerRef.current !== null) {
      clearTimeout(batchPollTimerRef.current);
      batchPollTimerRef.current = null;
    }
  };

  useEffect(() => {
    return () => stopBatchPolling();
  }, []);

  const resetState = () => {
    stopBatchPolling();
    setMethod("menu");
    setTokenInput("");
    setSessionInput("");
    setCodexAuthInput("");
    setPendingAccountJsonImport(null);
    setConfirmOpen(false);
    setOauthEmailHint("");
    setOauthSession(null);
    setOauthCallbackInput("");
    setOauthStarting(false);
    setBatchFile(null);
    setBatchFileLineCount(0);
    setBatchTextInput("");
    setBatchJob(null);
  };

  const handleOpenChange = (nextOpen: boolean) => {
    setOpen(nextOpen);
    if (!nextOpen) {
      resetState();
    }
  };

  const submitTokens = async (tokens: string[], successText?: string, accountPayloads: AccountImportPayload[] = []) => {
    const normalizedTokens = tokens.map((item) => item.trim()).filter(Boolean);

    if (normalizedTokens.length === 0) {
      toast.error("请先提供至少一个可用 Token");
      return;
    }

    setIsSubmitting(true);
    try {
      const data = await createAccounts(normalizedTokens, accountPayloads);
      onImported(data.items);
      setOpen(false);
      resetState();

      if ((data.errors?.length ?? 0) > 0) {
        const firstError = data.errors?.[0]?.error;
        toast.error(
          `${successText ?? "导入完成"}，新增 ${data.added ?? 0} 个，已刷新 ${data.refreshed ?? 0} 个，失败 ${data.errors?.length ?? 0} 个${firstError ? `，首个错误：${firstError}` : ""}`,
        );
      } else {
        toast.success(
          `${successText ?? "导入完成"}，新增 ${data.added ?? 0} 个，跳过 ${data.skipped ?? 0} 个重复项，已自动刷新账号信息`,
        );
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "导入账户失败";
      toast.error(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleImportTokenText = async () => {
    await submitTokens(splitTokens(tokenInput), "Access Token 导入完成");
  };

  const handleOAuthBatchFileSelected = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) {
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      toast.error("凭证文件不能超过 2MB");
      return;
    }
    try {
      const content = await readFileAsText(file);
      const lineCount = countCredentialLines(content);
      if (lineCount === 0) {
        toast.error("文件中没有读取到非空凭证行");
        return;
      }
      setBatchFile(file);
      setBatchFileLineCount(lineCount);
      toast.success(`已选择 ${file.name}（检测到 ${lineCount} 行记录）`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "读取凭证文件失败";
      toast.error(message);
    }
  };

  // 启动服务端批量 OAuth 登录任务并轮询进度，完成后刷新账号列表
  const handleStartOAuthBatch = async () => {
    if (!batchFile && !batchTextInput.trim()) {
      toast.error("请先选择凭证文件或粘贴账号列表");
      return;
    }

    setIsSubmitting(true);
    try {
      const job = await startOAuthBatchImport({
        file: batchFile,
        content: batchTextInput,
      });
      setBatchJob(job);
      setBatchFile(null);
      setBatchFileLineCount(0);
      setBatchTextInput("");
      toast.success(`已提交 ${job.total} 个账号，服务端正在逐个执行 OAuth 登录`);

      stopBatchPolling();
      const pollSeq = batchPollSeqRef.current;
      const pollJob = async () => {
        try {
          const latest = await fetchOAuthBatchImportJob(job.job_id);
          if (pollSeq !== batchPollSeqRef.current) {
            return;
          }
          setBatchJob(latest);
          if (latest.done) {
            stopBatchPolling();
            try {
              const refreshedAccounts = await fetchAccounts();
              onImported(refreshedAccounts.items);
            } catch {
              // 列表拉取失败不影响任务结果展示
            }
            if (latest.failed > 0 && latest.succeeded === 0) {
              toast.error(`批量 OAuth 登录结束：共 ${latest.total} 个，全部失败`);
            } else if (latest.failed > 0) {
              toast.error(
                `批量 OAuth 登录完成：成功 ${latest.succeeded} 个（新增 ${latest.added}），失败 ${latest.failed} 个`,
              );
            } else {
              toast.success(
                `批量 OAuth 登录完成：成功 ${latest.succeeded} 个，新增 ${latest.added} 个，已刷新账号信息`,
              );
            }
            return;
          }
          batchPollTimerRef.current = setTimeout(() => {
            void pollJob();
          }, 1000);
        } catch (pollError) {
          if (pollSeq !== batchPollSeqRef.current) {
            return;
          }
          stopBatchPolling();
          const msg = pollError instanceof Error ? pollError.message : "获取批量登录进度失败";
          toast.error(msg);
        }
      };
      batchPollTimerRef.current = setTimeout(() => {
        void pollJob();
      }, 1000);
    } catch (error) {
      const message = error instanceof Error ? error.message : "提交批量 OAuth 登录失败";
      toast.error(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  // 起授权：拿 authorize URL，立刻在新窗口打开，方便用户登录
  const handleStartOAuth = async () => {
    setOauthStarting(true);
    try {
      const data = await startOAuthLogin(oauthEmailHint.trim());
      setOauthSession(data);
      setOauthCallbackInput("");
      if (typeof window !== "undefined") {
        window.open(data.authorize_url, "_blank", "noopener,noreferrer");
      }
      toast.success("已打开 OpenAI 授权页面，请在登录后复制 callback URL 回来");
    } catch (error) {
      const message = error instanceof Error ? error.message : "OAuth 起始失败";
      toast.error(message);
    } finally {
      setOauthStarting(false);
    }
  };

  // 用粘贴回来的 callback URL 完成换 token + 落盘
  const handleFinishOAuth = async () => {
    if (!oauthSession) {
      toast.error("请先点击\"打开授权页面\"获取 session");
      return;
    }
    const trimmed = oauthCallbackInput.trim();
    if (!trimmed) {
      toast.error("请粘贴 callback URL 或 code");
      return;
    }

    setIsSubmitting(true);
    try {
      const data = await finishOAuthLogin(oauthSession.session_id, trimmed);
      onImported(data.items);
      setOpen(false);
      resetState();

      if ((data.errors?.length ?? 0) > 0) {
        const firstError = data.errors?.[0]?.error;
        toast.error(
          `OAuth 登录完成，新增 ${data.added ?? 0} 个，已刷新 ${data.refreshed ?? 0} 个，失败 ${data.errors?.length ?? 0} 个${firstError ? `，首个错误：${firstError}` : ""}`,
        );
      } else {
        toast.success(
          `OAuth 登录完成，新增 ${data.added ?? 0} 个，跳过 ${data.skipped ?? 0} 个重复项，已自动刷新账号信息`,
        );
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : "OAuth 换 token 失败";
      toast.error(message);
    } finally {
      setIsSubmitting(false);
    }
  };

  // 复制 authorize URL 到剪贴板（适配浏览器和 fallback）
  const handleCopyAuthorizeUrl = async () => {
    if (!oauthSession) {
      return;
    }
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(oauthSession.authorize_url);
        toast.success("授权 URL 已复制到剪贴板");
      } else {
        toast.error("当前环境不支持自动复制，请手动选择并复制");
      }
    } catch {
      toast.error("复制失败，请手动选择并复制");
    }
  };

  const handleTxtSelected = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    event.target.value = "";

    if (!file) {
      return;
    }

    try {
      const content = await readFileAsText(file);
      const tokens = splitTokens(content);

      if (tokens.length === 0) {
        toast.error("TXT 文件里没有读取到有效 Token");
        return;
      }

      setTokenInput((prev) => {
        const next = [...splitTokens(prev), ...tokens];
        return next.join("\n");
      });
      toast.success(`已从 ${file.name} 读取 ${tokens.length} 个 Token`);
    } catch (error) {
      const message = error instanceof Error ? error.message : "读取 TXT 文件失败";
      toast.error(message);
    }
  };

  const handleImportSessionJson = async () => {
    if (!sessionInput.trim()) {
      toast.error("请先粘贴完整 Session JSON");
      return;
    }

    try {
      const payload = JSON.parse(sessionInput) as unknown;
      const token = getSessionAccessToken(payload);

      if (!token) {
        toast.error("未从 Session JSON 中提取到 accessToken");
        return;
      }

      await submitTokens([token], "Session JSON 导入完成");
    } catch (error) {
      const message = error instanceof Error ? error.message : "Session JSON 解析失败";
      toast.error(message);
    }
  };

  const handleImportCodexAuthJson = async () => {
    if (!codexAuthInput.trim()) {
      toast.error("请先粘贴 Codex 认证 JSON");
      return;
    }

    try {
      const payload = JSON.parse(codexAuthInput) as unknown;
      const account = getCodexAuthAccount(payload);

      if (!account) {
        toast.error("未从 Codex 认证 JSON 中提取到 access_token");
        return;
      }

      await submitTokens([account.access_token], "Codex 认证 JSON 导入完成", [account]);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Codex 认证 JSON 解析失败";
      toast.error(message);
    }
  };

  const handleAccountJsonSelected = async (event: ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(event.target.files ?? []);
    event.target.value = "";

    if (files.length === 0) {
      return;
    }

    try {
      const results = await Promise.all(
        files.map(async (file) => {
          const raw = await readFileAsText(file);
          const parsed = JSON.parse(raw) as unknown;
          const accounts = getAccountJsonAccounts(parsed);
          return {
            accounts,
          };
        }),
      );

      const accounts = results.flatMap((item) => item.accounts);
      const tokens = accounts.map((item) => item.access_token);
      const parsedAccountCount = accounts.length;
      const errorCount = results.filter((item) => item.accounts.length === 0).length;

      if (parsedAccountCount === 0) {
        toast.error("这些账号 JSON 文件里没有读取到可用 access_token");
        return;
      }

      setPendingAccountJsonImport({
        tokens,
        accounts,
        parsedAccountCount,
        errorCount,
      });
      setConfirmOpen(true);
    } catch (error) {
      const message = error instanceof Error ? error.message : "读取账号 JSON 文件失败";
      toast.error(message);
    }
  };

  const renderMethodBody = () => {
    if (method === "token") {
      const tokenCount = splitTokens(tokenInput).length;

      return (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={() => setMethod("menu")}
              className="inline-flex items-center gap-1 text-sm text-stone-500 transition hover:text-stone-800"
            >
              <ArrowLeft className="size-4" />
              返回导入方式
            </button>
            <span className="text-xs text-stone-400">当前识别 {tokenCount} 个 Token</span>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-stone-700">Access Token 列表</label>
            <Textarea
              placeholder="每行一个 Access Token..."
              value={tokenInput}
              onChange={(event) => setTokenInput(event.target.value)}
              className="min-h-56 resize-none rounded-xl border-stone-200"
            />
          </div>
          <div className="rounded-2xl border border-dashed border-stone-200 bg-stone-50 p-4">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div className="space-y-1">
                <div className="text-sm font-medium text-stone-800">从 TXT 文件导入</div>
                <div className="text-sm leading-6 text-stone-500">支持 `.txt`，文件内容也是一行一个 Token。</div>
              </div>
              <Button
                type="button"
                variant="outline"
                className="rounded-xl border-stone-200 bg-white"
                onClick={() => txtInputRef.current?.click()}
                disabled={isSubmitting}
              >
                <FileText className="size-4" />
                选择 TXT
              </Button>
            </div>
          </div>
          <input
            ref={txtInputRef}
            type="file"
            accept=".txt,text/plain"
            className="hidden"
            onChange={(event) => void handleTxtSelected(event)}
          />
        </div>
      );
    }

    if (method === "session") {
      return (
        <div className="space-y-4">
          <button
            type="button"
            onClick={() => setMethod("menu")}
            className="inline-flex items-center gap-1 text-sm text-stone-500 transition hover:text-stone-800"
          >
            <ArrowLeft className="size-4" />
            返回导入方式
          </button>
          <div className="rounded-2xl border border-stone-200 bg-stone-50 p-4 text-sm leading-6 text-stone-600">
            打开
            {" "}
            <a
              href={sessionUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-medium text-stone-900 underline underline-offset-4"
            >
              {sessionUrl}
              <ExternalLink className="size-3.5" />
            </a>
            ，复制页面返回的完整 JSON，系统会自动提取其中的 `accessToken` 导入。
          </div>
          <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-900">
            <div className="font-medium">风险提示</div>
            <div>
              不要使用自己的大号，尽量使用不常用的小号进行导入，避免出现封号风险。本项目不承担任何封号风险责任。
            </div>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-stone-700">Session JSON</label>
            <Textarea
              placeholder='粘贴完整 JSON，例如包含 "accessToken" 的对象...'
              value={sessionInput}
              onChange={(event) => setSessionInput(event.target.value)}
              className="min-h-56 resize-none rounded-xl border-stone-200 font-mono text-xs"
            />
          </div>
        </div>
      );
    }

    if (method === "oauth") {
      return (
        <div className="space-y-4">
          <button
            type="button"
            onClick={() => setMethod("menu")}
            className="inline-flex items-center gap-1 text-sm text-stone-500 transition hover:text-stone-800"
          >
            <ArrowLeft className="size-4" />
            返回导入方式
          </button>
          <div className="rounded-2xl border border-stone-200 bg-stone-50 p-4 text-sm leading-6 text-stone-600 space-y-2">
            <div className="font-medium text-stone-800">操作步骤</div>
            <ol className="list-decimal pl-5 space-y-1">
              <li>（可选）填写你 ChatGPT 账号的邮箱，登录页会预填。</li>
              <li>点击下方"打开授权页面"，在新标签里登录自己的 ChatGPT 账号。</li>
              <li>登录完成后浏览器会跳到 <code className="rounded bg-stone-200 px-1">platform.openai.com/auth/callback?code=...</code>。立刻从地址栏复制整段 URL（或开 F12 在 Network 里抓到 callback 那一行，右键 Copy → Copy URL）。</li>
              <li>把 callback URL 粘到下面输入框，点"完成导入"。</li>
            </ol>
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium text-stone-700">邮箱（可选预填）</label>
            <input
              type="email"
              placeholder="you@example.com"
              value={oauthEmailHint}
              onChange={(event) => setOauthEmailHint(event.target.value)}
              disabled={Boolean(oauthSession) || oauthStarting}
              className="w-full rounded-xl border border-stone-200 bg-white px-3 py-2 text-sm outline-none focus:border-stone-400"
            />
          </div>
          {!oauthSession ? (
            <Button
              type="button"
              className="h-10 rounded-xl bg-stone-950 text-white hover:bg-stone-800"
              onClick={() => void handleStartOAuth()}
              disabled={oauthStarting}
            >
              {oauthStarting ? <LoaderCircle className="size-4 animate-spin" /> : <ExternalLink className="size-4" />}
              打开授权页面
            </Button>
          ) : (
            <div className="space-y-3">
              <div className="rounded-2xl border border-stone-200 bg-white p-3 text-xs leading-6 text-stone-600 break-all font-mono">
                {oauthSession.authorize_url}
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  type="button"
                  variant="outline"
                  className="rounded-xl border-stone-200 bg-white"
                  onClick={() => void handleCopyAuthorizeUrl()}
                >
                  <Copy className="size-4" />
                  复制授权 URL
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="rounded-xl border-stone-200 bg-white"
                  onClick={() => window.open(oauthSession.authorize_url, "_blank", "noopener,noreferrer")}
                >
                  <ExternalLink className="size-4" />
                  再次打开
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="rounded-xl border-stone-200 bg-white"
                  onClick={() => {
                    setOauthSession(null);
                    setOauthCallbackInput("");
                  }}
                >
                  重新生成
                </Button>
              </div>
              <div className="space-y-2">
                <label className="text-sm font-medium text-stone-700">粘贴 callback URL（或仅 code）</label>
                <Textarea
                  placeholder={"https://platform.openai.com/auth/callback?code=...&state=..."}
                  value={oauthCallbackInput}
                  onChange={(event) => setOauthCallbackInput(event.target.value)}
                  className="min-h-24 resize-none rounded-xl border-stone-200 font-mono text-xs"
                />
              </div>
            </div>
          )}
          <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm leading-6 text-amber-900">
            <div className="font-medium">注意</div>
            <div>
              授权码（code）只能使用一次。如果浏览器的 callback 页加载完成、显示了 OpenAI 的错误页，那 code 大概率已经被消耗，
              请点击"重新生成"再走一次。整个流程在 10 分钟内完成即可。
            </div>
          </div>
        </div>
      );
    }

    if (method === "oauth-batch") {
      const textLineCount = countCredentialLines(batchTextInput);
      const totalInputLines = batchFileLineCount + textLineCount;
      const batchRunning = Boolean(batchJob && !batchJob.done);
      const progressPercent =
        batchJob && batchJob.total > 0
          ? Math.min(100, Math.round((batchJob.processed / batchJob.total) * 100))
          : 0;

      return (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <button
              type="button"
              onClick={() => {
                stopBatchPolling();
                setBatchJob(null);
                setMethod("menu");
              }}
              disabled={batchRunning}
              className="inline-flex items-center gap-1 text-sm text-stone-500 transition hover:text-stone-800 disabled:opacity-50"
            >
              <ArrowLeft className="size-4" />
              返回导入方式
            </button>
            {!batchJob ? (
              <span className="text-xs text-stone-400">当前待提交约 {totalInputLines} 行</span>
            ) : (
              <span className="text-xs text-stone-500">
                {batchJob.done ? "任务已结束" : "服务端顺序登录中..."}
              </span>
            )}
          </div>

          {!batchJob ? (
            <>
              <div className="rounded-2xl border border-stone-200 bg-stone-50 p-4 text-sm leading-6 text-stone-600 space-y-1">
                <div className="font-medium text-stone-800">文件与格式说明</div>
                <div>
                  每行一条，格式为{" "}
                  <code className="rounded bg-white px-1.5 py-0.5 font-mono text-xs text-stone-800">
                    邮箱----密码----2FA密钥
                  </code>
                  （未开启 2FA 可仅填{" "}
                  <code className="rounded bg-white px-1.5 py-0.5 font-mono text-xs text-stone-800">
                    邮箱----密码
                  </code>
                  ，支持 <code className="font-mono text-xs">#</code> 注释行）。
                </div>
                <div className="text-xs text-stone-500">
                  服务端按标准 OAuth 逐个换取 Access Token 与 Refresh Token 并自动刷新入库；密码和 2FA 密钥仅在本次登录内存使用，不写入账号库。
                </div>
              </div>

              <div className="rounded-2xl border border-dashed border-stone-200 bg-stone-50 p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="space-y-1">
                    <div className="text-sm font-medium text-stone-800">上传凭证文件（TXT）</div>
                    <div className="text-sm leading-6 text-stone-500">
                      直接上传至远程服务器解析并执行批量 OAuth 登录（单文件上限 2MB）。
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    className="rounded-xl border-stone-200 bg-white"
                    onClick={() => oauthBatchFileInputRef.current?.click()}
                    disabled={isSubmitting}
                  >
                    <FileText className="size-4" />
                    选择凭证文件
                  </Button>
                </div>
                {batchFile ? (
                  <div className="mt-3 flex items-center justify-between rounded-xl border border-stone-200 bg-white px-3 py-2 text-xs text-stone-700">
                    <div className="truncate">
                      已选文件：<span className="font-medium text-stone-900">{batchFile.name}</span>（检测到 {batchFileLineCount} 行）
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setBatchFile(null);
                        setBatchFileLineCount(0);
                      }}
                      className="ml-2 rounded p-1 text-stone-400 hover:bg-stone-100 hover:text-stone-700"
                      aria-label="移除文件"
                    >
                      <X className="size-3.5" />
                    </button>
                  </div>
                ) : null}
              </div>
              <input
                ref={oauthBatchFileInputRef}
                type="file"
                accept=".txt,.csv,text/plain"
                className="hidden"
                onChange={(event) => void handleOAuthBatchFileSelected(event)}
              />

              <div className="space-y-2">
                <label className="text-sm font-medium text-stone-700">或直接粘贴账号列表（可选）</label>
                <Textarea
                  placeholder={"user1@example.com----YourPassword----JBSWY3DPEHPK3PXP\nuser2@example.com----YourPassword----JBSWY3DPEHPK3PXQ"}
                  value={batchTextInput}
                  onChange={(event) => setBatchTextInput(event.target.value)}
                  className="min-h-36 resize-none rounded-xl border-stone-200 font-mono text-xs"
                />
              </div>
            </>
          ) : (
            <div className="space-y-3">
              <div className="rounded-2xl border border-stone-200 bg-stone-50 p-4 space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2 font-medium text-stone-800">
                    {batchRunning ? <LoaderCircle className="size-4 animate-spin text-amber-600" /> : null}
                    <span>
                      {batchRunning
                        ? `正在登录：${batchJob.current_email || "准备中..."}`
                        : batchJob.status === "completed"
                          ? "批量 OAuth 登录已完成"
                          : "批量 OAuth 登录结束（全部失败）"}
                    </span>
                  </div>
                  <span className="font-mono text-xs text-stone-600">
                    {batchJob.processed}/{batchJob.total} ({progressPercent}%)
                  </span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-stone-200">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-amber-400 to-orange-500 transition-all duration-300"
                    style={{ width: `${progressPercent}%` }}
                  />
                </div>
                <div className="grid grid-cols-4 gap-2 text-center text-xs">
                  <div className="rounded-xl bg-white px-2 py-2 border border-stone-200">
                    <div className="text-stone-400">成功</div>
                    <div className="mt-0.5 font-semibold text-emerald-700">{batchJob.succeeded}</div>
                  </div>
                  <div className="rounded-xl bg-white px-2 py-2 border border-stone-200">
                    <div className="text-stone-400">新增入库</div>
                    <div className="mt-0.5 font-semibold text-stone-900">{batchJob.added}</div>
                  </div>
                  <div className="rounded-xl bg-white px-2 py-2 border border-stone-200">
                    <div className="text-stone-400">已刷新</div>
                    <div className="mt-0.5 font-semibold text-stone-900">{batchJob.refreshed}</div>
                  </div>
                  <div className="rounded-xl bg-white px-2 py-2 border border-stone-200">
                    <div className="text-stone-400">失败</div>
                    <div className="mt-0.5 font-semibold text-rose-600">{batchJob.failed}</div>
                  </div>
                </div>
              </div>

              {batchJob.parse_errors.length > 0 ? (
                <div className="rounded-2xl border border-amber-200 bg-amber-50 p-3 text-xs text-amber-900 space-y-1">
                  <div className="font-medium">
                    已忽略 {batchJob.parse_errors.length} 行格式异常/重复记录：
                  </div>
                  <div className="max-h-24 overflow-y-auto space-y-0.5 font-mono">
                    {batchJob.parse_errors.map((err, idx) => (
                      <div key={`${err.line}-${idx}`}>
                        第 {err.line} 行{err.email ? ` (${err.email})` : ""}：{err.error}
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              <div className="rounded-2xl border border-stone-200 bg-white">
                <div className="border-b border-stone-100 px-3.5 py-2 text-xs font-medium text-stone-500">
                  逐条执行结果（{batchJob.results.length}/{batchJob.total}）
                </div>
                <div className="max-h-56 divide-y divide-stone-100 overflow-y-auto">
                  {batchJob.results.length === 0 ? (
                    <div className="px-3.5 py-6 text-center text-xs text-stone-400">
                      等待首个账号返回结果...
                    </div>
                  ) : (
                    batchJob.results.map((item, idx) => (
                      <div key={`${item.email}-${idx}`} className="flex items-start justify-between gap-3 px-3.5 py-2.5 text-xs">
                        <div className="min-w-0 flex-1">
                          <div className="truncate font-mono text-stone-800">{item.email}</div>
                          {item.error ? (
                            <div className={cn("mt-0.5 break-all", item.ok ? "text-amber-700" : "text-rose-600")}>
                              {item.error}
                            </div>
                          ) : (
                            <div className="mt-0.5 text-stone-400">
                              {item.added > 0 ? "已新增入库" : "已更新已有账号"}
                              {item.refreshed > 0 ? " · 已刷新额度" : ""}
                            </div>
                          )}
                        </div>
                        {item.ok ? (
                          <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
                            <CheckCircle2 className="size-3.5" />
                            成功
                          </span>
                        ) : (
                          <span className="inline-flex shrink-0 items-center gap-1 rounded-full bg-rose-50 px-2 py-0.5 font-medium text-rose-700">
                            <XCircle className="size-3.5" />
                            失败
                          </span>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      );
    }

    if (method === "account-json") {
      return (
        <div className="space-y-4">
          <button
            type="button"
            onClick={() => setMethod("menu")}
            className="inline-flex items-center gap-1 text-sm text-stone-500 transition hover:text-stone-800"
          >
            <ArrowLeft className="size-4" />
            返回导入方式
          </button>
          <div className="rounded-2xl border border-dashed border-stone-200 bg-stone-50 p-5">
            <div className="space-y-2">
              <div className="text-sm font-medium text-stone-800">选择本地账号 JSON 文件</div>
              <div className="text-sm leading-6 text-stone-500">
                支持本项目导出的单账号对象或全部账号数组，也兼容每个文件一个账号对象的 CPA JSON。
                系统会自动提取 `access_token` 或 `accessToken`。
              </div>
            </div>
            <Button
              type="button"
              className="mt-4 rounded-xl bg-stone-950 text-white hover:bg-stone-800"
              onClick={() => accountJsonInputRef.current?.click()}
              disabled={isSubmitting}
            >
              <Files className="size-4" />
              选择 JSON 文件
            </Button>
          </div>
          <input
            ref={accountJsonInputRef}
            type="file"
            accept=".json,application/json"
            multiple
            className="hidden"
            onChange={(event) => void handleAccountJsonSelected(event)}
          />
          {pendingAccountJsonImport ? (
            <div className="rounded-2xl border border-stone-200 bg-white p-4 text-sm leading-6 text-stone-600">
              最近一次读取到 {pendingAccountJsonImport.parsedAccountCount} 个 Token
              {pendingAccountJsonImport.errorCount > 0 ? `，另有 ${pendingAccountJsonImport.errorCount} 个文件未提取成功` : ""}。
            </div>
          ) : null}
        </div>
      );
    }

    if (method === "codex-auth") {
      return (
        <div className="space-y-4">
          <button
            type="button"
            onClick={() => setMethod("menu")}
            className="inline-flex items-center gap-1 text-sm text-stone-500 transition hover:text-stone-800"
          >
            <ArrowLeft className="size-4" />
            返回导入方式
          </button>
          <div className="space-y-2">
            <label className="text-sm font-medium text-stone-700">Codex 认证 JSON</label>
            <Textarea
              placeholder='粘贴包含 "access_token"、"refresh_token"、"id_token" 的 Codex 认证 JSON...'
              value={codexAuthInput}
              onChange={(event) => setCodexAuthInput(event.target.value)}
              className="min-h-64 resize-none rounded-xl border-stone-200 font-mono text-xs"
            />
          </div>
        </div>
      );
    }

    return (
      <div className="space-y-3">
        <MethodCard
          title="OAuth 登录已有账号（带自动刷新）"
          description="用浏览器登录自己的 ChatGPT 账号，回填 callback URL 即可拿到 refresh_token，后台会自动续期。"
          icon={LogIn}
          onClick={() => setMethod("oauth")}
        />
        <MethodCard
          title="批量 OAuth 登录导入（账号密码 + 2FA 文件）"
          description="上传 TXT 凭证文件或粘贴「邮箱----密码----2FA密钥」，服务端逐个走 OAuth 登录换票并自动刷新入库。"
          icon={Upload}
          onClick={() => setMethod("oauth-batch")}
        />
        <MethodCard
          title="导入 Access Token"
          description="支持直接粘贴，一行一个；也支持从 TXT 文件读取，一行一个。"
          icon={KeyRound}
          onClick={() => setMethod("token")}
        />
        <MethodCard
          title="导入 Session JSON"
          description="从 chatgpt.com 的 session 接口复制完整 JSON，自动提取 accessToken。"
          icon={FileJson}
          onClick={() => setMethod("session")}
        />
        <MethodCard
          title="导入 Codex 认证 JSON"
          description="粘贴 Codex 认证 JSON，导入后账号来源标记为 codex。"
          icon={FileJson}
          onClick={() => setMethod("codex-auth")}
        />
        <MethodCard
          title="导入账号 JSON 文件"
          description="支持本项目导出的单账号 JSON 或全部账号数组，也兼容 CPA JSON 文件。"
          icon={Files}
          onClick={() => setMethod("account-json")}
        />
        <MethodCard
          title="从远程 CPA 服务器导入"
          description="前往设置页面配置远程 CPA 服务器后再执行导入。"
          icon={Files}
          onClick={() => {
            setOpen(false);
            resetState();
            router.push("/settings");
          }}
        />
        <MethodCard
          title="从 Sub2API 服务器导入"
          description="前往设置页面配置 Sub2API 服务器，再选择其中的 OpenAI 账号导入。"
          icon={ServerCog}
          onClick={() => {
            setOpen(false);
            resetState();
            router.push("/settings");
          }}
        />
      </div>
    );
  };

  const footerDisabled = disabled || isSubmitting;

  return (
    <>
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <Button
          className="h-10 rounded-xl bg-stone-950 px-4 text-white hover:bg-stone-800"
          onClick={() => setOpen(true)}
          disabled={disabled}
        >
          <Upload className="size-4" />
          导入
        </Button>
        <DialogContent showCloseButton={false} className="max-h-[90vh] overflow-y-auto rounded-2xl p-6">
          <DialogHeader className="gap-2">
            <DialogTitle>
              {method === "menu"
                ? "导入账户"
                : method === "token"
                  ? "导入 Access Token"
                  : method === "session"
                    ? "导入 Session JSON"
                    : method === "codex-auth"
                      ? "导入 Codex 认证 JSON"
                    : method === "oauth"
                      ? "OAuth 登录已有账号"
                    : method === "oauth-batch"
                      ? "批量 OAuth 登录导入"
                      : "导入账号 JSON"}
            </DialogTitle>
            <DialogDescription className="text-sm leading-6">
              {method === "menu"
                ? "选择一种导入方式。导入成功后会自动拉取邮箱、类型和额度。"
                : method === "token"
                  ? "支持手动粘贴或从 TXT 文件导入，一行一个 Token。"
                  : method === "session"
                    ? "粘贴完整 Session JSON，系统会自动提取 accessToken。"
                    : method === "codex-auth"
                      ? "粘贴 Codex 认证 JSON，系统会按 codex 来源导入。"
                    : method === "oauth"
                      ? "用浏览器跑一遍 OpenAI 标准 OAuth，拿回 refresh_token 后系统会自动续期。"
                    : method === "oauth-batch"
                      ? "上传凭证文件或粘贴账号列表，服务端按标准 OAuth 逐个登录并刷新入库。"
                      : "支持读取本项目导出的单账号对象或全部账号数组，并在提交前做数量确认。"}
            </DialogDescription>
          </DialogHeader>

          {renderMethodBody()}

          <DialogFooter className="pt-2">
            <Button
              variant="secondary"
              className="h-10 rounded-xl bg-stone-100 px-5 text-stone-700 hover:bg-stone-200"
              onClick={() => handleOpenChange(false)}
              disabled={footerDisabled}
            >
              {method === "oauth-batch" && batchJob ? (batchJob.done ? "关闭" : "后台继续并关闭") : "取消"}
            </Button>
            {method === "token" ? (
              <Button
                className="h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800"
                onClick={() => void handleImportTokenText()}
                disabled={footerDisabled}
              >
                {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : null}
                导入 Token
              </Button>
            ) : null}
            {method === "session" ? (
              <Button
                className="h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800"
                onClick={() => void handleImportSessionJson()}
                disabled={footerDisabled}
              >
                {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : null}
                导入 JSON
              </Button>
            ) : null}
            {method === "codex-auth" ? (
              <Button
                className="h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800"
                onClick={() => void handleImportCodexAuthJson()}
                disabled={footerDisabled}
              >
                {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : null}
                导入 JSON
              </Button>
            ) : null}
            {method === "oauth" ? (
              <Button
                className={cn(
                  "h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800",
                  !oauthSession ? "hidden" : "",
                )}
                onClick={() => void handleFinishOAuth()}
                disabled={footerDisabled || !oauthSession || !oauthCallbackInput.trim()}
              >
                {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : null}
                完成导入
              </Button>
            ) : null}
            {method === "oauth-batch" && !batchJob ? (
              <Button
                className="h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800"
                onClick={() => void handleStartOAuthBatch()}
                disabled={footerDisabled || (!batchFile && !batchTextInput.trim())}
              >
                {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : null}
                开始批量 OAuth 登录
              </Button>
            ) : null}
            {method === "oauth-batch" && batchJob?.done ? (
              <Button
                className="h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800"
                onClick={() => {
                  stopBatchPolling();
                  setBatchJob(null);
                }}
              >
                继续导入新一批
              </Button>
            ) : null}
            {method === "account-json" ? (
              <Button
                className={cn(
                  "h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800",
                  !pendingAccountJsonImport ? "hidden" : "",
                )}
                onClick={() => setConfirmOpen(true)}
                disabled={footerDisabled || !pendingAccountJsonImport}
              >
                查看导入确认
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent className="rounded-2xl p-6">
          <DialogHeader className="gap-2">
            <DialogTitle>确认导入账号 Token</DialogTitle>
            <DialogDescription className="text-sm leading-6">
              {pendingAccountJsonImport
                ? `确认识别到 ${pendingAccountJsonImport.parsedAccountCount} 个 Token，是否确认导入？`
                : "尚未读取到可导入的 Token。"}
              {pendingAccountJsonImport?.errorCount
                ? `，另有 ${pendingAccountJsonImport.errorCount} 个文件未提取成功。`
                : "。"}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="pt-2">
            <Button
              variant="secondary"
              className="h-10 rounded-xl bg-stone-100 px-5 text-stone-700 hover:bg-stone-200"
              onClick={() => setConfirmOpen(false)}
              disabled={isSubmitting}
            >
              返回
            </Button>
            <Button
              className="h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800"
              onClick={() =>
                void submitTokens(
                  pendingAccountJsonImport?.tokens ?? [],
                  "账号 JSON 导入完成",
                  pendingAccountJsonImport?.accounts ?? [],
                )
              }
              disabled={isSubmitting || !pendingAccountJsonImport}
            >
              {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : null}
              确认导入
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
