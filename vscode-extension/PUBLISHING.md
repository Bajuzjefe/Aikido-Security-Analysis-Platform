# Publishing the Aikido VS Code Extension

## Prerequisites

1. **Azure DevOps account** — sign up at https://dev.azure.com
2. **Personal Access Token (PAT)** with `Marketplace (Manage)` scope
3. **Publisher ID** — already set to `Bajuzjefe` in package.json

## One-time setup

### 1. Create Azure DevOps PAT

1. Go to https://dev.azure.com
2. Sign in with your Microsoft account
3. Click your profile icon (top right) > **Personal access tokens**
4. Click **New Token**
5. Set:
   - **Name**: `vsce-publish`
   - **Organization**: `All accessible organizations`
   - **Expiration**: 1 year (max)
   - **Scopes**: Click **Custom defined** > check **Marketplace > Manage**
6. Click **Create** and copy the token immediately (you won't see it again)

### 2. Create the publisher (first time only)

Go to https://marketplace.visualstudio.com/manage and create publisher `Bajuzjefe` if it doesn't exist yet. Use the same Microsoft account as your PAT.

### 3. Log in with vsce

```bash
cd vscode-extension
npx vsce login Bajuzjefe
# Paste your PAT when prompted
```

## Publishing

### Build and publish in one step

```bash
cd vscode-extension
npm install
npm run publish
```

This runs `tsc` then `vsce publish`, which increments nothing — it publishes whatever version is in `package.json` (currently 0.3.0).

### Or build .vsix first, then publish manually

```bash
cd vscode-extension
npm install
npm run package          # produces aikido-vscode-0.3.0.vsix
npx vsce publish --packagePath aikido-vscode-0.3.0.vsix
```

### Bump version and publish

```bash
npx vsce publish minor   # 0.3.0 -> 0.4.0
npx vsce publish patch   # 0.3.0 -> 0.3.1
```

## Updating

When releasing a new Aikido version:

1. Update `version` in `vscode-extension/package.json` to match
2. Run `npm run publish`

## Verify

After publishing, the extension appears at:
https://marketplace.visualstudio.com/items?itemName=Bajuzjefe.aikido-vscode

Users install with:
```
ext install Bajuzjefe.aikido-vscode
```

## Troubleshooting

- **"publisher not found"**: Create it at https://marketplace.visualstudio.com/manage
- **"unauthorized"**: PAT expired or missing Marketplace scope — regenerate
- **compilation errors**: Run `npm install` first to get @types/node and @types/vscode
