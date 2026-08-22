import { render } from 'preact'
import { App } from './app'
import { I18nProvider } from './i18n'
import './styles.css'

const root = document.getElementById('app')
if (root) {
  render(
    <I18nProvider>
      <App />
    </I18nProvider>,
    root,
  )
}
