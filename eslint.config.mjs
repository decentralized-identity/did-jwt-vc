import prettierPlugin from 'eslint-plugin-prettier'
import js from '@eslint/js'
import typescriptEslint from '@typescript-eslint/eslint-plugin'
import { rules as configPrettierRules } from 'eslint-config-prettier'
import { rules as configPrettierOverridesRules } from 'eslint-config-prettier/prettier'

const prettierRules = Object.fromEntries(
  Object.entries({ ...configPrettierRules, ...configPrettierOverridesRules }).filter(([, v]) => v !== 0)
)

export default [
  js.configs.recommended,
  ...typescriptEslint.configs['flat/recommended'],
  {
    plugins: { prettier: prettierPlugin },
    rules: { 'prettier/prettier': 'error', ...prettierRules },
  },
  { ignores: ['src/__tests__/**'] },
]
