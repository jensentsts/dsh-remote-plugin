/** Model-facing change measurement with DSH's canonical fixed-density heuristic; not a provider tokenizer. */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { estimateToolsTokens } from '@deepseek-ai/dsh-token-meter/src/estimate.ts'
import { createRunTools } from '../src/remote-runs.ts'

const legacySourceSentence = '本机在对端那里扮演"用户"；**把远端对话当作本机的一个 subagent / task**：'
const producerSourceSentence = '输入在对端标记为 dsh-remote 来源（不是对端本地真人）；**把远端对话当作本机的一个 subagent / task**：'
const beforeDescription = '给**正在跑的远端任务追加指示**，或给空闲的远端会话发一条新消息；'
  + '与 `remote_agent_prompt` 的区别是**不阻塞等交付**：消息塞进对端的收件箱就返回，'
  + '正在跑的轮次结束后由下一轮消化，空闲时立即开始一轮。\n'
  + '定位会话的优先级：run_id（该运行所用的远端会话）→ session_id → 本 chat 自己那段远端对话。'
  + '多条不同指示可以连续发，但前提是真有必要；不要用它重复 `remote_agent_prompt` 已经发过的任务。'

test('tool definitions disclose source and explicit modes once, with measured prompt growth', () => {
  const source = readFileSync(new URL('../src/client.ts', import.meta.url), 'utf8')
  assert.ok(source.includes(producerSourceSentence))
  assert.equal(source.includes(legacySourceSentence), false)
  const send = createRunTools({ resolveSession() {}, startPrompt() {}, sendMessage() {}, interrupt() {}, rememberScope() {}, log() {}, maxRuns: () => 1 }).find(tool => tool.name === 'remote_send_message')
  assert.deepEqual(send.parameters.properties.mode.enum, ['queue', 'steer', 'auto'])
  const after = { name: send.name, description: send.description, parameters: send.parameters }
  const { mode: _mode, ...beforeProperties } = send.parameters.properties
  const before = { ...after, description: beforeDescription, parameters: { ...send.parameters, properties: beforeProperties } }
  const measure = tool => estimateToolsTokens({ tools: [tool] })
  const result = { heuristic: 'DSH token-meter estimateToolsTokens, 4 chars/token plus framing',
    remoteSendMessage: { before: measure(before), after: measure(after), delta: measure(after) - measure(before) },
    remotePromptSourceSentence: { before: Math.ceil(legacySourceSentence.length / 4), after: Math.ceil(producerSourceSentence.length / 4) },
  }
  console.log(JSON.stringify(result))
})
