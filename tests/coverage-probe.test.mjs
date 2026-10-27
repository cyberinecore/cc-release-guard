// Coverage probe: one row per real publish or deploy command. SEEN means the hook answers `ask`,
// MISS means it stays silent. Every SEEN row must also match at least one `if` filter in
// hooks/hooks.json, or Claude Code never spawns the hook for it in the first place.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = resolve(dirname(fileURLToPath(import.meta.url)), '../cli/shipsafe.mjs');
const HOOKS = JSON.parse(readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../hooks/hooks.json'), 'utf8'));
const FILTERS = HOOKS.hooks.PreToolUse.flatMap((e) => e.hooks.map((h) => h.if));
const root = mkdtempSync(join(tmpdir(), 'shipsafe-probe-'));

function write(dir, files) {
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  return dir;
}

function hook(command, cwd) {
  const r = spawnSync('node', [CLI, 'hook'], {
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd, hook_event_name: 'PreToolUse' }),
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  return r.stdout ? JSON.parse(r.stdout).hookSpecificOutput : null;
}

// Claude Code's `Bash(<glob>)` filter: `*` matches any text, the pattern spans the whole command.
function filterMatches(command) {
  return FILTERS.some((f) => {
    const glob = /^Bash\((.*)\)$/s.exec(f)[1];
    const re = new RegExp(`^${glob.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`, 's');
    return re.test(command);
  });
}

// A JS project whose scripts and Makefile hide publishes, with a leaky build output.
const proj = write(join(root, 'proj'), {
  'package.json': JSON.stringify({
    name: 'probe', version: '1.0.0', private: true,
    scripts: {
      build: 'tsc -p .', test: 'node --test', lint: 'eslint .',
      release: 'npm publish', ship: 'npm run release', deploy: 'npm run build && wrangler pages deploy dist --project-name probe',
      'publish:all': 'lerna publish from-package', prepublishOnly: 'npm run build', postpublish: 'git push --tags',
      'deploy:s3': 'aws s3 sync dist s3://probe-bucket/site',
    },
  }),
  Makefile: [
    'DIST = dist',
    'BUCKET = s3://probe-bucket',
    '',
    'build:',
    '\tnpm run build',
    '',
    'test:',
    '\tnpm test',
    '',
    'publish: build',
    '\t@npm publish',
    '',
    'deploy: build',
    '\taws s3 sync $(DIST) $(BUCKET)/site --delete',
    '',
    'release:',
    '\t$(MAKE) publish',
    '',
    '.PHONY: build test publish deploy release',
    '',
  ].join('\n'),
  'dist/app.js': 'a();\n//# sourceMappingURL=app.js.map\n',
  'dist/app.js.map': '{"version":3}',
  'clean/index.html': '<html></html>\n',
  'src/app.ts': 'export const a = 1;\n',
  '.github/workflows/release.yml': "name: release\non:\n  push:\n    tags:\n      - 'v*'\njobs:\n  publish:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npm publish\n",
  '.git/HEAD': 'ref: refs/heads/main\n',
  '.git/refs/tags/v1.2.3': '0000000000000000000000000000000000000000\n',
  '.claude/shipsafe.json': JSON.stringify({ askOnTagPush: true }),
});
// The same tree without the opt-in and without a tag-triggered workflow.
const plain = write(join(root, 'plain'), {
  'package.json': JSON.stringify({ name: 'plain', version: '1.0.0', scripts: { build: 'tsc', release: 'npm publish' } }),
  '.git/HEAD': 'ref: refs/heads/main\n',
  '.git/refs/tags/v1.2.3': '0000000000000000000000000000000000000000\n',
  'dist/index.html': '<html></html>\n',
  '.vercel/output/static/index.html': '<html></html>\n',
});
// JSR packages: one leaks a map next to its TypeScript source, the other only has gitignored files.
const jsrLeak = write(join(root, 'jsr-leak'), {
  'jsr.json': JSON.stringify({ name: '@probe/leak', version: '0.1.0', exports: './mod.ts' }),
  'mod.ts': 'export const a = 1;\n',
  'mod.js.map': '{"version":3}',
});
const jsrClean = write(join(root, 'jsr-clean'), {
  'deno.json': JSON.stringify({ name: '@probe/clean', version: '0.1.0', exports: './mod.ts', publish: { exclude: ['fixtures/'] } }),
  'mod.ts': 'export const a = 1;\n',
  '.gitignore': '.env\nbuild/\n',
  '.env': 'TOKEN=1\n',
  'build/out.js.map': '{}',
  'fixtures/app.js.map': '{}',
});
const empty = write(join(root, 'empty'), { 'README.md': 'nothing here\n' });
// Shell scripts: two named for a deploy, one run with a deploy verb, two that must stay silent.
write(proj, {
  'scripts/deploy-frontend.sh': '#!/bin/sh\n# aws s3 sync is the deploy\nset -e\naws s3 sync dist s3://probe-bucket/site\n',
  'scripts/cf.sh': '#!/usr/bin/env bash\ncase "$1" in\n  deploy) npx wrangler pages deploy dist --project-name probe ;;\n  status) echo ok ;;\nesac\n',
  'scripts/build.sh': '#!/bin/sh\nnpm publish\n',
  'scripts/release-mac.sh': '#!/bin/sh\nxcrun notarytool submit app.zip --wait\n',
});

// Real git repositories with a bare remote, for the askOnBranchPush opt-in.
const git = (cwd, ...args) => {
  const r = spawnSync('git', ['-c', 'user.name=probe', '-c', 'user.email=probe@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
};
const fakeToken = 'gh' + 'p_' + 'A'.repeat(36);
function gitRepo(name, files) {
  const dir = write(join(root, name), files);
  mkdirSync(join(root, `${name}.git`));
  git(join(root, `${name}.git`), 'init', '--bare', '-q');
  git(dir, 'init', '-q', '-b', 'main');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'init');
  git(dir, 'remote', 'add', 'origin', join(root, `${name}.git`));
  git(dir, 'push', '-q', 'origin', 'main');
  return dir;
}
const branchy = gitRepo('branchy', {
  'README.md': 'hi\n',
  '.claude/shipsafe.json': JSON.stringify({ askOnBranchPush: ['main'] }),
  '.github/workflows/deploy.yml': "name: deploy\non:\n  push:\n    branches: [production]\njobs:\n  d:\n    runs-on: ubuntu-latest\n    steps:\n      - run: aws s3 sync dist s3://b\n",
});
write(branchy, { '.env': 'TOKEN=1\n', 'config.js': `export const t = '${fakeToken}';\n` });
git(branchy, 'add', '-A');
git(branchy, 'commit', '-q', '-m', 'leak');
write(branchy, { 'config.js': 'export const t = process.env.T;\n' });
git(branchy, 'add', '-A');
git(branchy, 'commit', '-q', '-m', 'remove the token, which history still holds');
git(branchy, 'branch', 'feature');
const clean = gitRepo('clean-push', {
  'README.md': 'hi\n',
  '.claude/shipsafe.json': JSON.stringify({ askOnBranchPush: ['main'] }),
});
write(clean, { 'docs.md': 'more\n' });
git(clean, 'add', '-A');
git(clean, 'commit', '-q', '-m', 'docs');
const bitbucket = gitRepo('bitbucket', {
  'README.md': 'hi\n',
  '.claude/shipsafe.json': JSON.stringify({ askOnBranchPush: true }),
  'bitbucket-pipelines.yml': "pipelines:\n  branches:\n    development:\n      - step:\n          script:\n            - aws s3 sync dist s3://b\n    '{uat-sat,production-sat}':\n      - step:\n          script:\n            - aws s3 sync dist s3://c\n",
});
write(bitbucket, { 'id_rsa': 'not really a key\n' });
git(bitbucket, 'add', '-A');
git(bitbucket, 'commit', '-q', '-m', 'oops');
const noOptIn = gitRepo('no-opt-in', { 'README.md': 'hi\n' });
write(noOptIn, { '.env': 'TOKEN=1\n' });
git(noOptIn, 'add', '-A');
git(noOptIn, 'commit', '-q', '-m', 'env');

const SEEN = 'SEEN';
const MISS = 'MISS';
const rows = [
  // 1. script wrappers
  [SEEN, 'npm run release', proj, /via npm run release/],
  [SEEN, 'pnpm run release', proj, /via pnpm run release/],
  [SEEN, 'yarn run release', proj, /via yarn run release/],
  [SEEN, 'bun run release', proj, /via bun run release/],
  [SEEN, 'npm run ship', proj, /via npm run ship > npm run release/],
  [SEEN, 'npm run deploy', proj, /source-map/],
  [SEEN, 'npm run publish:all', proj, /lerna publish/],
  [SEEN, 'npm run deploy:s3', proj, /source-map/],
  [SEEN, 'cd proj && npm run release', root, /via npm run release/],
  [SEEN, 'npm run-script release', proj],
  [SEEN, 'npm run release -- --otp 123456', proj],
  [SEEN, 'make publish', proj, /via make publish/],
  [SEEN, 'make deploy', proj, /source-map/],
  [SEEN, 'make release', proj, /via make release > make publish/],
  [SEEN, 'make -C proj publish', root],
  [SEEN, 'make -f Makefile publish', proj],
  [MISS, 'npm run build', proj],
  [MISS, 'npm run test', proj],
  [MISS, 'npm run lint', proj],
  [MISS, 'npm test', proj],
  [MISS, 'npm run release', empty],
  [MISS, 'npm run nonexistent', proj],
  [MISS, 'make test', proj],
  [MISS, 'make build', proj],
  [MISS, 'make', proj],
  [MISS, 'make publish', empty],
  // 2. bucket and server deploys
  [SEEN, 'aws s3 sync dist s3://probe-bucket/site', proj, /source-map/],
  [SEEN, 'aws s3 sync ./dist/ s3://probe-bucket --delete --cache-control max-age=60', proj, /source-map/],
  [SEEN, 'aws s3 cp dist s3://probe-bucket/ --recursive', proj, /source-map/],
  [SEEN, 'aws --profile prod s3 cp --recursive ./dist s3://probe-bucket', proj, /source-map/],
  [SEEN, 'aws s3 sync $BUILD_DIR s3://probe-bucket', proj, /shell expansion|cannot tell/],
  [SEEN, 'aws s3 sync missing s3://probe-bucket', proj, /not found/],
  [SEEN, 'gsutil -m rsync -r dist gs://probe-bucket', proj, /source-map/],
  [SEEN, 'gsutil cp -r dist gs://probe-bucket/', proj, /source-map/],
  [SEEN, 'gcloud storage rsync dist gs://probe-bucket --recursive', proj, /source-map/],
  [SEEN, 'gcloud storage cp -r dist gs://probe-bucket', proj, /source-map/],
  [SEEN, "az storage blob upload-batch -s dist -d '$web' --account-name probe", proj, /source-map/],
  [SEEN, 'az storage blob upload-batch --source ./dist --destination web --account-name probe --overwrite', proj, /source-map/],
  [SEEN, 'azcopy copy dist https://probe.blob.core.windows.net/web --recursive', proj, /source-map/],
  [SEEN, 'azcopy sync dist "https://probe.blob.core.windows.net/web?sv=1"', proj, /source-map/],
  [SEEN, 'rclone sync dist remote:probe-bucket/site', proj, /source-map/],
  [SEEN, 'rclone copy -P dist r2:probe-bucket', proj, /source-map/],
  [SEEN, 'rsync -avz dist/ deploy@host.example:/var/www/site', proj, /source-map/],
  [SEEN, 'rsync -a --delete -e "ssh -p 2222" dist/ host:/srv/www', proj, /source-map/],
  [SEEN, 'rsync -a dist rsync://host/module/site', proj, /source-map/],
  [SEEN, 'rsync -avze ssh dist/ host:/srv/www', proj, /source-map/],
  [SEEN, 'fly deploy -v -a probe', proj, /cannot see the artifact/],
  [SEEN, 'gcloud functions deploy fn --gen2 --runtime nodejs20 --trigger-http --source .', proj, /cannot see the artifact/],
  [SEEN, 'git push --signed origin v1.2.3', proj, /release\.yml/],
  [SEEN, 'scp -r dist user@host:/var/www', proj, /source-map/],
  [SEEN, 'scp -P 2222 -r ./dist host:/var/www', proj, /source-map/],
  [MISS, 'aws s3 ls', proj],
  [MISS, 'aws s3 ls s3://probe-bucket', proj],
  [MISS, 'aws s3 cp s3://probe-bucket/x .', proj],
  [MISS, 'aws s3 sync s3://probe-bucket/site dist', proj],
  [MISS, 'aws s3 cp dist/app.js s3://probe-bucket/', proj],
  [MISS, 'aws s3 sync clean s3://probe-bucket', proj],
  [MISS, 'gsutil ls gs://probe-bucket', proj],
  [MISS, 'gsutil cp gs://probe-bucket/x .', proj],
  [MISS, 'gcloud storage ls', proj],
  [MISS, 'az storage blob list -c web', proj],
  [MISS, 'azcopy list https://probe.blob.core.windows.net/web', proj],
  [MISS, 'rclone ls remote:', proj],
  [MISS, 'rclone copy remote:probe-bucket dist', proj],
  [MISS, 'rsync -a src/ backup/', proj],
  [MISS, 'rsync -avze ssh host:/srv/x ./local', proj],
  [MISS, 'rsync -a host:/srv/x ./local', proj],
  [MISS, 'rsync -avz clean/ host:/srv/www', proj],
  [MISS, 'scp host:file .', proj],
  [MISS, 'scp dist/app.js host:/tmp/', proj],
  // 3. more registries and platforms
  [SEEN, 'jsr publish', jsrLeak, /source-map/],
  [SEEN, 'deno publish', jsrLeak, /source-map/],
  [SEEN, 'npx jsr publish', jsrLeak, /source-map/],
  [SEEN, 'vsce publish', proj, /vsce package/],
  [SEEN, 'npx vsce publish -p $VSCE_PAT', proj, /vsce package/],
  [SEEN, 'vsce publish minor', proj, /vsce package/],
  [SEEN, 'ovsx publish', proj, /ovsx/],
  [SEEN, 'pnpm dlx ovsx publish -p token', proj, /ovsx/],
  [SEEN, 'vsce publish --packagePath missing.vsix', proj, /not found/],
  [SEEN, 'vsce publish -i missing.vsix', proj, /not found/],
  [SEEN, 'vercel --prod', proj, /cannot see the artifact/],
  [SEEN, 'vercel deploy --prod --yes', proj, /cannot see the artifact/],
  [SEEN, 'vercel', proj, /cannot see the artifact/],
  [SEEN, 'npx vercel --prod', proj, /cannot see the artifact/],
  [SEEN, 'fly deploy', proj, /cannot see the artifact/],
  [SEEN, 'flyctl deploy --remote-only', proj, /cannot see the artifact/],
  [SEEN, 'railway up', proj, /cannot see the artifact/],
  [SEEN, 'gcloud run deploy svc --source .', proj, /cannot see the artifact/],
  [SEEN, 'gcloud run deploy svc --source=. --region us-central1', proj, /cannot see the artifact/],
  [SEEN, 'gcloud app deploy', proj, /cannot see the artifact/],
  [SEEN, 'sam deploy --guided', proj, /cannot see the artifact/],
  [SEEN, 'cdk deploy', proj, /cannot see the artifact/],
  [SEEN, 'npx cdk deploy MyStack --require-approval never', proj, /cannot see the artifact/],
  [SEEN, 'serverless deploy --stage prod', proj, /cannot see the artifact/],
  [SEEN, 'sls deploy', proj, /cannot see the artifact/],
  [SEEN, 'goreleaser release --clean', proj, /names no artifact/],
  [SEEN, 'goreleaser release', proj, /names no artifact/],
  [SEEN, 'mvn deploy', proj, /names no artifact/],
  [SEEN, 'mvn clean deploy -DskipTests', proj, /names no artifact/],
  [SEEN, './mvnw deploy', proj, /names no artifact/],
  [SEEN, 'gradle publish', proj, /names no artifact/],
  [SEEN, './gradlew publishToMavenCentral', proj, /names no artifact/],
  [SEEN, './gradlew publishPlugins', proj, /names no artifact/],
  [SEEN, './gradlew clean publish --no-daemon', proj, /names no artifact/],
  [MISS, 'jsr publish --dry-run', jsrLeak],
  [MISS, 'deno publish --dry-run', jsrLeak],
  [MISS, 'jsr publish', jsrClean],
  [MISS, 'deno publish', jsrClean],
  [MISS, 'deno run main.ts', jsrLeak],
  [MISS, 'jsr add @std/path', jsrLeak],
  [MISS, 'vsce package', proj],
  [MISS, 'vsce ls', proj],
  [MISS, 'vercel dev', proj],
  [MISS, 'vercel build', proj],
  [MISS, 'vercel env ls', proj],
  [MISS, 'vercel deploy --prebuilt', plain],
  [MISS, 'fly logs', proj],
  [MISS, 'fly status', proj],
  [MISS, 'railway logs', proj],
  [MISS, 'railway run npm start', proj],
  [MISS, 'gcloud run deploy svc --image gcr.io/p/svc', proj],
  [MISS, 'gcloud run services list', proj],
  [MISS, 'gcloud app logs tail', proj],
  [MISS, 'sam build', proj],
  [MISS, 'cdk synth', proj],
  [MISS, 'cdk diff', proj],
  [MISS, 'serverless invoke -f hello', proj],
  [MISS, 'sls info', proj],
  [MISS, 'goreleaser release --snapshot --clean', proj],
  [MISS, 'goreleaser build', proj],
  [MISS, 'goreleaser release --skip=publish', proj],
  [MISS, 'mvn install', proj],
  [MISS, 'mvn package', proj],
  [MISS, 'gradle build', proj],
  [MISS, './gradlew publishToMavenLocal', proj],
  [MISS, './gradlew test', proj],
  // 4. release-tag pushes (opt-in)
  [SEEN, 'git push --tags', proj, /askOnTagPush/],
  [SEEN, 'git push origin --tags', proj, /askOnTagPush/],
  [SEEN, 'git push --follow-tags origin main', proj, /askOnTagPush/],
  [SEEN, 'git push origin v1.2.3', proj, /release\.yml/],
  [SEEN, 'git push origin refs/tags/v1.2.3', proj, /release\.yml/],
  [SEEN, 'git push origin tag v1.2.3', proj, /release\.yml/],
  [SEEN, 'git push origin main v1.2.3', proj, /release\.yml/],
  [SEEN, 'git -C proj push --tags', root, /askOnTagPush/],
  [MISS, 'git push', proj],
  [MISS, 'git push origin main', proj],
  [MISS, 'git push -u origin feature/x', proj],
  [MISS, 'git push --tags --dry-run', proj],
  [MISS, 'git push origin :refs/tags/v1.2.3', proj],
  [MISS, 'git push --delete origin v1.2.3', proj],
  [MISS, 'git push --tags', plain],
  [MISS, 'git push origin v1.2.3', plain],
  [MISS, 'git tag v1.2.3', proj],
  // 7. branch pushes and PR merges that deploy (opt-in askOnBranchPush)
  [SEEN, 'git push origin main', branchy, /lands on main, which \.claude\/shipsafe\.json[\s\S]*sensitive-file\s+\.env[\s\S]*secret-token\s+config\.js/],
  [SEEN, 'git push', branchy, /lands on main/],
  [SEEN, 'git push -u origin HEAD', branchy, /lands on main/],
  [SEEN, 'git push origin main:production', branchy, /lands on production, which \.github\/workflows\/deploy\.yml/],
  [SEEN, 'git push --all origin', branchy, /lands on main/],
  [SEEN, 'git push origin HEAD:uat-sat', bitbucket, /bitbucket-pipelines\.yml[\s\S]*sensitive-file\s+id_rsa/],
  [SEEN, 'git push origin main:development', bitbucket, /lands on development/],
  [SEEN, 'gh pr merge 12 --squash', branchy, /merges on the server.*main, production/],
  [MISS, 'git push origin feature', branchy],
  [MISS, 'git push origin main --dry-run', branchy],
  [MISS, 'git push origin main', clean],
  [MISS, 'git push origin main', bitbucket],
  [MISS, 'git push origin main', noOptIn],
  [MISS, 'gh pr merge 12', noOptIn],
  [MISS, 'gh pr view 12', branchy],
  // 8. shell scripts named for a release, or run with a release verb
  [SEEN, 'bash scripts/deploy-frontend.sh', proj, /via scripts\/deploy-frontend\.sh: .*source-map/s],
  [SEEN, './scripts/deploy-frontend.sh', proj, /source-map/],
  [SEEN, 'scripts/cf.sh deploy', proj, /via scripts\/cf\.sh deploy/],
  [SEEN, 'sh scripts/cf.sh deploy', proj, /source-map/],
  [MISS, 'bash scripts/cf.sh status', proj],
  [MISS, 'bash scripts/build.sh', proj],
  [MISS, 'bash scripts/release-mac.sh', proj],
  [MISS, 'bash scripts/deploy-frontend.sh', empty],
  // must stay silent
  [MISS, 'echo "npm publish"', proj],
  [MISS, 'grep publish README.md', proj],
  [MISS, 'git commit -m "release: npm publish later"', proj],
  [MISS, 'cat Makefile', proj],
];

for (const [expect, command, cwd, reason] of rows) {
  test(`${expect} ${command}`, () => {
    const out = hook(command, cwd);
    if (expect === MISS) {
      assert.equal(out, null, out?.permissionDecisionReason);
      return;
    }
    assert.equal(out?.permissionDecision, 'ask', 'the hook stayed silent');
    if (reason) assert.match(out.permissionDecisionReason, reason);
    assert.ok(filterMatches(command), `no hooks.json if-filter matches: ${command}`);
  });
}
