check:
	bun run check

# Verify and publish the platform package before the portable root package.
publish:
	bun run verify
	bun publish --cwd packages/darwin-arm64
	bun publish
