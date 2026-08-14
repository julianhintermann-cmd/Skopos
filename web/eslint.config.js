import js from '@eslint/js'
import tseslint from 'typescript-eslint'
import reactHooks from 'eslint-plugin-react-hooks'

// The project had no linter, and two chart files carried
// `eslint-disable-next-line react-hooks/exhaustive-deps` for a rule that had
// never run. The comments were not suppressing anything; they were a note that
// someone knew the dependencies were wrong, in the two components most likely
// to be hurt by it.
//
// The rule set is deliberately small. A linter that reports a hundred style
// opinions on its first run gets switched off, and the point here is the
// handful of rules that catch the defects this codebase actually had: stale
// closures over polling state, effects that miss a dependency, and promises
// nobody awaits.
export default tseslint.config(
  { ignores: ['dist', 'node_modules', 'screenshots.mjs'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    plugins: { 'react-hooks': reactHooks },
    languageOptions: {
      globals: {
        window: 'readonly',
        document: 'readonly',
        navigator: 'readonly',
        localStorage: 'readonly',
        fetch: 'readonly',
        EventSource: 'readonly',
        AbortSignal: 'readonly',
        DOMException: 'readonly',
        ResizeObserver: 'readonly',
        MediaQueryList: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        console: 'readonly',
        Intl: 'readonly',
        matchMedia: 'readonly',
        getComputedStyle: 'readonly',
        HTMLElement: 'readonly',
        HTMLInputElement: 'readonly',
        HTMLDivElement: 'readonly',
        SVGSVGElement: 'readonly',
        Response: 'readonly',
        RequestInit: 'readonly',
        Event: 'readonly',
        KeyboardEvent: 'readonly',
        URLSearchParams: 'readonly',
        Blob: 'readonly',
        URL: 'readonly',
      },
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Unused values are usually a half-finished edit, but an argument named
      // with a leading underscore is a deliberate "this exists to match a
      // signature" and stays quiet.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      // `any` erases exactly the contract this release spent its time getting
      // right, so it warns rather than passing silently.
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
)
