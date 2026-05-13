import eslintPluginReact from 'eslint-plugin-react'
import tsParser from '@typescript-eslint/parser'

export default [
  {
    ignores: ['dist']
  },
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        document: 'readonly',
        window: 'readonly',
        fetch: 'readonly'
      }
    },
    plugins: {
      react: eslintPluginReact
    },
    rules: {
      'react/jsx-uses-react': 'off',
      'react/react-in-jsx-scope': 'off'
    }
  }
]
