/**
 * The model-facing half of "a remote conversation is a subagent".
 *
 * The DSH-native way to expose a provider is a separate `tool-subagent` row in
 * the composition. Doing it here instead means **one switch** turns the feature
 * on: the plugin registers the `remote` provider and this tool together, with no
 * profile edit and no risk of a tool-name collision with a row the operator also
 * added. What the row would add on top is background runs; foreground delegation
 * is what makes the remote conversation show up as a subagent in the first place.
 *
 * The name matters: the chat classifies any `subagent`/`subagent_*` tool as
 * delegation, so `subagent_remote` is what gets it grouped with the other
 * subagent work instead of looking like an ordinary tool call.
 *
 * Kept free of cordis by taking a facade: the service is injected by the caller,
 * so this module is unit-testable with a fake run.
 *
 * @module dsh-remote/subagent-tool
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import type { JsonValue } from '@deepseek-ai/dsh-util-values'
import type { ContentBlock } from '@deepseek-ai/dsh-llm'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { renderRemoteReplies } from './reply-codec.ts'
import type { RemoteReply, ReplyFormat } from './reply-codec.ts'

/** The terminal shape this tool reads off a run, structurally the seam's result. */
export interface RemoteRunResult {
  readonly output: readonly ContentBlock[]
  readonly stopReason: string
  readonly diagnostic?: string
  readonly replies?: readonly RemoteReply[]
  readonly replyFormat?: ReplyFormat
}

/** A published run, reduced to what this tool uses. */
export interface RemoteRunHandle {
  readonly id: string
  readonly result: Promise<RemoteRunResult>
  dispose(): Promise<void>
}

/** The slice of `ctx.subagents` this tool drives. */
export interface RemoteSubagentFacade {
  start(name: string, request: {
    readonly label?: string
    readonly prompt: readonly ContentBlock[]
    readonly parent: Agent
    readonly signal: AbortSignal
  }): Promise<RemoteRunHandle>
}

/** Join the text blocks of a run's output. */
export function resultText(output: readonly ContentBlock[]): string {
  const parts: string[] = []
  for (const block of output) {
    const typed = block as { type?: unknown, text?: unknown }
    if (typed?.type === 'text' && typeof typed.text === 'string') parts.push(typed.text)
  }
  return parts.join('\n').trim()
}

/** The tool's name; also what makes the chat treat it as delegation. */
export const REMOTE_SUBAGENT_TOOL = 'subagent_remote'

/**
 * Build the delegation tool over one provider.
 *
 * @param subagents - the subagent registry (usually `ctx.subagents`).
 * @param providerName - the registered provider to start runs on.
 * @returns a tool definition to register in the global layer.
 */
export function createRemoteSubagentTool(
  subagents: RemoteSubagentFacade,
  providerName = 'remote',
) {
  return defineTool({
    name: REMOTE_SUBAGENT_TOOL,
    description:
      '把一个子任务**委派给对端 harness** 执行——远端对话在本机就是一个 subagent / task：'
      + '你派活、它交付，最后把结论带回本机上下文。\n'
      + '会话规则（严格）：**同一个本机 chat 永远复用同一段远端对话**（插件按本机会话推导 id），'
      + '所以连续委派是接着同一个上下文，不会每次新开。\n'
      + '本机优先：能在本机上下文里完成的事不要委派；委派时写清目标、边界和交付物。\n'
      + '打断：本机用户中断会同时中断对端那一轮；若返回里带 interrupted 标记，'
      + '立刻停下、不要重试，把决定权交回用户。',
    parameters: {
      description: { type: 'string', required: true, description: '这次委派的简短标题（3-5 个词）。' },
      prompt: { type: 'string', required: true, description: '交给对端 agent 的完整任务描述。' },
    },
    output: {
      schema: { type: 'json' },
      render: (_args, value) => {
        const v = value as unknown as {
          sessionId?: string, stopReason?: string, diagnostic?: string | null,
          reply?: string, interrupted?: boolean,
        }
        const head = [
          `session: ${v.sessionId ?? '?'}`,
          `stop   : ${v.stopReason ?? '?'}${v.interrupted === true ? '  (interrupted)' : ''}`,
        ]
        if (v.diagnostic !== undefined && v.diagnostic !== null && v.diagnostic !== '') {
          head.push(`error  : ${v.diagnostic}`)
        }
        if (v.interrupted === true) {
          head.push('⚠️ 远端这一轮被中断，没有可用的交付。立刻停止，等用户的新指示。')
        }
        head.push('--- deliverable ---')
        return [{ type: 'text' as const, text: [...head, renderRemoteReplies(value)].join('\n') }]
      },
    },
    async execute(
      args: { description: string, prompt: string },
      exec: { agent?: Agent, signal?: AbortSignal },
    ): Promise<JsonValue> {
      const parent = exec?.agent
      if (parent === undefined) {
        throw new Error(`${REMOTE_SUBAGENT_TOOL}: no calling agent, so there is nobody to delegate from`)
      }
      const run = await subagents.start(providerName, {
        label: args.description,
        prompt: [{ type: 'text', text: args.prompt }],
        parent,
        signal: exec.signal ?? new AbortController().signal,
      })
      try {
        const result = await run.result
        return {
          sessionId: run.id,
          stopReason: result.stopReason,
          interrupted: result.stopReason === 'aborted',
          diagnostic: result.diagnostic ?? null,
          reply: resultText(result.output),
          ...(result.replies === undefined ? {} : { replies: result.replies }),
          ...(result.replyFormat === undefined ? {} : { replyFormat: result.replyFormat }),
        } as unknown as JsonValue
      } finally {
        // The seam requires disposal on every path; for a settled run this is a
        // no-op by construction (the provider only stops the peer if the work was
        // still outstanding).
        await run.dispose()
      }
    },
  })
}
