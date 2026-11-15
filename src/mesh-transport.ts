/** Late service lookup keeps direct-only deployments independent of the mesh row. */
import type { Context } from '@deepseek-ai/cordis'
import type { Socket } from 'node:net'
import type { EndpointConfig } from './link.ts'

export function meshSocketFactory(ctx: Context): (config: EndpointConfig) => Promise<Socket> {
  return async config => {
    const target = config.relayTarget
    if (typeof target !== 'string' || target === '') throw new Error('A mesh target identity is required')
    const mesh = (ctx as unknown as { get(name: string): unknown }).get('dshRemoteMesh') as { open(target: string): Promise<Socket> } | undefined
    if (mesh === undefined) throw new Error('Enable and configure the mesh connection before using relayTarget')
    return await mesh.open(target)
  }
}
