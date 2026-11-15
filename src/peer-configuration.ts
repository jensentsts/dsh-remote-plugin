/** One live declaration projection shared by default tools, pools and @ routing. */
import type { PeerProfile } from './peers.ts'
export interface PeerConfiguration extends PeerProfile {
  peers?: Record<string, PeerProfile>
  peerName?: string
  defaultPeer?: string
}

export function configuredPeers(config: PeerConfiguration): Record<string, PeerProfile> {
  const peers = Object.fromEntries(Object.entries(config.peers ?? {}).map(([name, value]) => [name, { ...value }]))
  const legacy = config.peerName?.trim() || 'default'
  if (!Object.hasOwn(peers, legacy) && (config.host?.trim() || Number(config.port) > 0 || config.relayTarget)) {
    peers[legacy] = {
      host: config.host, port: config.port, relayTarget: config.relayTarget, privateKey: config.privateKey,
      privateKeyFile: config.privateKeyFile, autoGenerateKey: config.autoGenerateKey,
      peerPublicKey: config.peerPublicKey, peerPublicKeyFile: config.peerPublicKeyFile,
      timeoutMs: config.timeoutMs, maxPermission: 3,
      allowLegacyHandshake: config.allowLegacyHandshake, maxSessionMs: config.maxSessionMs,
    }
  }
  return peers
}

/** An invalid configured default is an error, never a silent switch to another host. */
export function configuredDefaultPeer(config: PeerConfiguration): string {
  const peers = configuredPeers(config)
  const wanted = config.defaultPeer?.trim()
  if (wanted) {
    if (!Object.hasOwn(peers, wanted)) throw new Error(`Unknown default peer "${wanted}"`)
    return wanted
  }
  return Object.keys(peers)[0] ?? ''
}

export function defaultEndpoint(config: PeerConfiguration): PeerProfile {
  const peers = configuredPeers(config)
  const name = configuredDefaultPeer(config)
  return name === '' ? {} : peers[name]!
}
