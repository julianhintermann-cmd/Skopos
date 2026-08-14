// The primitive barrel.
//
// The primitives themselves live in ./ui/. This file re-exports them so that
// every existing `from '../components/ui'` import keeps resolving — a file
// beats a directory in both TypeScript's and Vite's resolution order, so the
// split cost zero call-site churn.
//
// Rules these primitives exist to enforce:
//   - colour comes from a token, never a hex and never an inline style, so that
//     hover / active / disabled can be expressed at all;
//   - a value that is not known is rendered as words, never as an em-dash and
//     never as a substituted zero;
//   - a tone is never the only channel carrying the meaning.

export type { Tone, Size, ToneInput } from './ui/tone'
export { toneOf, toneText, toneQuiet, toneFill } from './ui/tone'

export { Card, CardHeader, Divider } from './ui/card'
export { NoData, Label, Code, StaleBadge } from './ui/text'
export { Button, IconButton } from './ui/button'
export { TextInput, Field, Toggle, Segmented } from './ui/input'
export type { SegmentedOption } from './ui/input'
export { StatTile, KeyValue } from './ui/stat'
export { Pill, SeverityBadge, Banner } from './ui/badge'
export { Table, Th, Td } from './ui/table'
export { EmptyState, Spinner, Skeleton, useToast, ToastHost } from './ui/feedback'
export type { ToastSpec } from './ui/feedback'
export { Modal } from './ui/modal'
