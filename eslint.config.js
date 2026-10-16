// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['node_modules/', 'dist/', 'coverage/', 'test-results/', 'playwright-report/'],
  },
  js.configs.recommended,
  // 型情報を使うルールを有効にする。認証コードでは「Promise の await 忘れ」や
  // 「any の素通り」がそのまま脆弱性になりうるため、型なしの推奨セットでは足りない。
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ['eslint.config.js'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  {
    files: ['**/*.js'],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    // 画面の JavaScript はブラウザで動く。ブラウザの全体変数と、<script> で読む SimpleWebAuthn を知らせる
    // （globals パッケージを足さずに済むよう、使うものだけを列挙する）
    files: ['src/web/**/*.js'],
    languageOptions: {
      sourceType: 'script',
      globals: {
        window: 'readonly',
        document: 'readonly',
        location: 'readonly',
        fetch: 'readonly',
        SimpleWebAuthnBrowser: 'readonly',
      },
    },
  },
);
