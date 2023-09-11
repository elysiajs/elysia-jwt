module.exports = {
    "env": {
        "es2021": true,
        "node": true
    },
    "extends": [
        "eslint:recommended",
        "plugin:@typescript-eslint/recommended"
    ],
    "parser": "@typescript-eslint/parser",
    "parserOptions": {
        "ecmaVersion": "latest",
        "sourceType": "module"
    },
    "plugins": [
        "@typescript-eslint"
    ],
    "rules": {
        "@typescript-eslint/consistent-type-imports": ["error", {
            "prefer": "type-imports",
        }],
        "@typescript-eslint/ban-types": 'off',
        '@typescript-eslint/no-explicit-any': 'off'
    },
    "ignorePatterns": ["example/*", "tests/**/*"]
}
