// A stylesheet imported for its side effect, which is what main.tsx does with
// styles.css. TypeScript 7 refuses a side-effect import it has no declaration
// for; earlier versions let it pass silently. Vite ships this in vite/client,
// but that pulls in a large ambient surface for one line, and the project uses
// exactly one such import.
declare module '*.css'

// world-atlas ships TopoJSON without type declarations.
declare module 'world-atlas/land-110m.json' {
  const value: unknown
  export default value
}
