# action-ci

This is a Github Action for Bluetooth Next CI.

## Run and report

When the PR is created with set of patches, CI job starts and runs the tests.
If any of test fails, it send email to the submitter via mailing list by replying to the original email with failure details and update the result to PR comment.
If all tests pass, no report send to the submitter but it still updates the result to PR comment.

## Configuration

[config.ini](./config.ini) contains some configuration for test. See the file for details.

## Test Covered

Following tests are covered.

### CheckPatch

Run checkpatch.pl

### Check gitlint

This test runs `gitlint` and its configuration is in [gitlint](./gitlint) file.

```ini
gitlint

[title-max-length]
line-length=72

[body-min-length]
min-length=1
```

### Checkbuild

Run make to build
