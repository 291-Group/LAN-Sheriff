import { createContext } from 'preact'
import { setTimeLocale } from '../api'
import { useContext, useEffect, useState, useCallback } from 'preact/hooks'
import { en, type Catalog } from './en'

/**
 * Every language except English is loaded on demand.
 *
 * Twelve catalogues is 291 KB of source, and bundling all of them put the
 * application within a few kilobytes of its size budget while eleven of the
 * twelve were dead weight for any given reader. English stays in the main
 * bundle because it is the default, the fallback, and the type the others are
 * checked against; the rest become their own chunks that Vite emits separately
 * and the browser fetches only if chosen.
 */
const loaders: Record<Exclude<Lang, 'en'>, () => Promise<{ default?: Catalog } & Record<string, Catalog>>> = {
  fr: () => import('./fr'),
  es: () => import('./es'),
  de: () => import('./de'),
  ar: () => import('./ar'),
  he: () => import('./he'),
  ja: () => import('./ja'),
  zh: () => import('./zh'),
  hi: () => import('./hi'),
  pt: () => import('./pt'),
  ru: () => import('./ru'),
  bn: () => import('./bn'),
}

/** Catalogues already fetched, so switching back is instant. */
const loaded: Partial<Record<Lang, Catalog>> = { en }

async function loadCatalog(lang: Lang): Promise<Catalog> {
  if (loaded[lang]) return loaded[lang]!
  if (lang === 'en') return en
  try {
    const mod = await loaders[lang]()
    const cat = (mod as any)[lang] as Catalog
    loaded[lang] = cat
    return cat
  } catch {
    // A chunk that will not load must not leave the interface blank. English is
    // always present, and a readable page in the wrong language beats an empty
    // one in the right language.
    return en
  }
}

export type Lang = 'en' | 'fr' | 'es' | 'de' | 'ar' | 'he' | 'ja' | 'zh' | 'hi' | 'pt' | 'ru' | 'bn'

/** Direction is needed before a catalogue has loaded, so it is kept separately
 *  rather than read from one. */
const DIRECTIONS: Record<Lang, 'ltr' | 'rtl'> = {
  en: 'ltr', fr: 'ltr', es: 'ltr', de: 'ltr', pt: 'ltr', ru: 'ltr',
  ja: 'ltr', zh: 'ltr', hi: 'ltr', bn: 'ltr',
  ar: 'rtl', he: 'rtl',
}

/** Languages offered in the picker, in the order shown. English leads because
 *  it is the default; the rest are alphabetical by their English name. */
export const LANGUAGES: { id: Lang; native: string; english: string }[] = [
  { id: 'en', native: 'English', english: 'English' },
  { id: 'ar', native: 'العربية', english: 'Arabic' },
  { id: 'bn', native: 'বাংলা', english: 'Bengali' },
  { id: 'zh', native: '中文', english: 'Chinese' },
  { id: 'fr', native: 'Français', english: 'French' },
  { id: 'de', native: 'Deutsch', english: 'German' },
  { id: 'he', native: 'עברית', english: 'Hebrew' },
  { id: 'hi', native: 'हिन्दी', english: 'Hindi' },
  { id: 'ja', native: '日本語', english: 'Japanese' },
  { id: 'pt', native: 'Português', english: 'Portuguese' },
  { id: 'ru', native: 'Русский', english: 'Russian' },
  { id: 'es', native: 'Español', english: 'Spanish' },
]

const STORAGE_KEY = 'sheriff-lang'

/**
 * Resolves the starting language.
 *
 * English is the default even for a browser set to something else: this is a
 * Canadian product shipped in English first, and a deliberate choice is better
 * than guessing from a header. A saved preference always wins.
 */
export function initialLang(): Lang {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    if (saved && saved in DIRECTIONS) return saved as Lang
  } catch {
    /* private browsing */
  }
  return 'en'
}

/** Arabic and Hebrew are written right to left. */
export function dirFor(lang: Lang): 'ltr' | 'rtl' {
  return DIRECTIONS[lang] ?? 'ltr'
}

/**
 * Applies language and direction to the document.
 *
 * Written synchronously rather than from an effect, for the same reason the
 * theme is: the canvas map reads computed styles, and effects run child-first,
 * so an effect here would let a child read the previous direction.
 */
export function applyLang(lang: Lang) {
  document.documentElement.lang = lang
  document.documentElement.dir = dirFor(lang)
  // Relative times are formatted by Intl rather than from these catalogues, so
  // they need telling separately. Done here because this is the one function
  // every language change goes through, including the first one at startup.
  setTimeLocale(lang)
  try {
    localStorage.setItem(STORAGE_KEY, lang)
  } catch {
    /* private browsing; the choice just will not persist */
  }
}

interface I18nValue {
  lang: Lang
  setLang: (l: Lang) => void
  t: Catalog
  dir: 'ltr' | 'rtl'
}

const I18nContext = createContext<I18nValue>({
  lang: 'en',
  setLang: () => {},
  t: en,
  dir: 'ltr',
})

export function I18nProvider({ children }: { children: preact.ComponentChildren }) {
  const [lang, setLangState] = useState<Lang>(initialLang)
  const [catalog, setCatalog] = useState<Catalog>(() => loaded[initialLang()] ?? en)
  // True until the chosen catalogue has arrived. Rendering English first and
  // swapping would be a visible flash of the wrong language on every load for
  // anyone who does not read English, which is precisely the audience the
  // translations exist for.
  const [pending, setPending] = useState(() => initialLang() !== 'en')

  const setLang = useCallback((l: Lang) => {
    applyLang(l)
    setLangState(l)
    const cached = loaded[l]
    if (cached) {
      setCatalog(cached)
      return
    }
    // Switching languages after load: the interface is already on screen, so a
    // brief moment in the previous language is better than blanking it.
    loadCatalog(l).then(setCatalog)
  }, [])

  useEffect(() => {
    applyLang(lang)
    if (pending) {
      loadCatalog(lang).then((c) => {
        setCatalog(c)
        setPending(false)
      })
    }
  }, [])

  if (pending) return null

  return (
    <I18nContext.Provider value={{ lang, setLang, t: catalog, dir: dirFor(lang) }}>
      {children}
    </I18nContext.Provider>
  )
}

export function useI18n(): I18nValue {
  return useContext(I18nContext)
}

/**
 * Fills {placeholders} in a translated string.
 *
 * Deliberately not a template literal: translators need to be able to move a
 * placeholder to wherever it belongs in their language, which means the string
 * has to carry named holes rather than positional interpolation.
 */
export function fill(template: string, values: Record<string, string | number>): string {
  return template.replace(/\{(\w+)\}/g, (whole, key) =>
    key in values ? String(values[key]) : whole,
  )
}

/** Formats a count using the viewer's locale digits and grouping. */
export function num(n: number, lang: Lang): string {
  try {
    return new Intl.NumberFormat(lang).format(n)
  } catch {
    return String(n)
  }
}
