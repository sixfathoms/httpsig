# Releasing

Pushing a tag runs the matching `release-*.yml` workflow, which tests, publishes and creates a GitHub Release. Versions come from the tag; nothing in the tree needs bumping.

| Language | Tag | Published to |
|---|---|---|
| Go | `golang/v1.2.3` | proxy.golang.org (the tag itself) |
| Swift | `1.2.3` | SwiftPM (the tag itself) |
| TypeScript | `ts/v1.2.3` | npm: `@sixfathoms/httpsig` |
| Java | `java/v1.2.3` | Maven Central: `dev.sixfathoms:httpsig`, `-okhttp`, `-jdk-http`, `-spring-webclient` |
| Kotlin | `kotlin/v1.2.3` | Maven Central: `dev.sixfathoms:httpsig-kotlin`, `-okhttp`, `-ktor` |

Go and Swift versions exist as soon as the tag is pushed, before the workflow's tests run, so check CI on the commit first. npm and Maven Central versions cannot be replaced once published.

The npm and Maven workflows run in the `release` GitHub environment, which only `ts/v*`, `java/v*` and `kotlin/v*` tags can use.

## One-time setup

### npm

The workflow uses [trusted publishing](https://docs.npmjs.com/trusted-publishers), so there is no token to store. The package has to exist before a trusted publisher can be added:

1. Publish the first version by hand: `cd typescript && npm ci && npm run build && npm login && npm publish --access public`.
2. In the package settings on npmjs.com, add a GitHub Actions trusted publisher: organization `sixfathoms`, repository `httpsig`, workflow `release-typescript.yml`, environment `release`. Allow `npm publish`, not only staged publishing.
3. Release through the workflow within 2 days, or npm expires the configuration.

### Maven Central

1. Verify the `dev.sixfathoms` namespace at [central.sonatype.com](https://central.sonatype.com/publishing/namespaces) and generate a user token.
2. Create a signing key and publish its public half to `keyserver.ubuntu.com`.
3. Store four secrets in the `release` environment:

```bash
gh secret set SONATYPE_USERNAME --env release
gh secret set SONATYPE_PASSWORD --env release
gpg --armor --export-secret-keys KEY_ID | gh secret set GPG_SIGNING_KEY --env release
gh secret set GPG_SIGNING_PASSWORD --env release
```

To rehearse without publishing: `./gradlew publishToMavenLocal` in `java/` or `kotlin/`.
