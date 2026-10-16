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
    // 画面のスクリプトはブラウザで動く。Node の globals ではなくブラウザの名前を既知として扱う
    files: ['src/web/**/*.js'],
    languageOptions: {
      globals: {
        document: 'readonly',
        location: 'readonly',
        fetch: 'readonly',
        FormData: 'readonly',
      },
    },
  },
);
