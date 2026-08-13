// Minimal i18n scaffold. English is the only locale in v1, but strings live
// here (not inline) so a German translation is a matter of adding a dictionary
// — no component changes.

const en = {
  'nav.overview': 'Overview',
  'nav.live': 'Live',
  'nav.traffic': 'Traffic',
  'nav.domains': 'Domains',
  'nav.devices': 'Devices',
  'nav.firewall': 'Firewall',
  'nav.alerts': 'Alerts',
  'nav.cloudflare': 'Cloudflare',
  'nav.settings': 'Settings',
  'nav.system': 'System',
  'section.monitor': 'Monitor',
  'section.protect': 'Protect',
  'section.manage': 'Manage',
  'action.logout': 'Log out',
  'action.block': 'Block',
  'action.unblock': 'Unblock',
  'action.ack': 'Acknowledge',
  'action.acknowledge_all': 'Acknowledge all',
  'label.enforcing': 'Enforcing',
  'label.observing': 'Observing',
  'label.sampling': 'Sampling',
} as const

type Key = keyof typeof en

const dictionaries: Record<string, Partial<Record<Key, string>>> = { en }

let locale = 'en'

export function setLocale(l: string) {
  if (dictionaries[l]) locale = l
}

export function t(key: Key): string {
  return dictionaries[locale]?.[key] ?? en[key] ?? key
}
